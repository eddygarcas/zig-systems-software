/// AEAD File Encryption Tool
///
/// Encrypts and decrypts files using ChaCha20-Poly1305 authenticated encryption.
/// Passwords are turned into keys via PBKDF2-HMAC-SHA256 with a random salt.
/// Files are processed in fixed-size chunks, each independently authenticated
/// with a per-chunk nonce derived from a random base nonce and a counter.
///
/// Binary format:
///   [Header] [Chunk 0] [Chunk 1] ... [Chunk N]
///
/// Each chunk:
///   [4-byte LE ciphertext length] [ciphertext] [16-byte Poly1305 tag]
const std = @import("std");

/// 8-byte magic number identifying the file format.
const MAGIC = "RZAEAD1\n";
/// File format version.
const VERSION: u8 = 1;

/// Length of the random salt used for PBKDF2 key derivation (bytes).
const SaltLen = 16;
/// ChaCha20-Poly1305 symmetric key length (bytes).
const KeyLen = 32;
/// Poly1305 authentication tag length (bytes).
const TagLen = 16;
/// ChaCha20-Poly1305 nonce length (bytes).
const NonceLen = 12;
/// Default plaintext chunk size: 64 KiB.
const ChunkSizeDefault: u32 = 64 * 1024;
/// Maximum allowed chunk size: 4 MiB.
const MaxChunkSide: u32 = 4 * 1024 * 1024;
/// PBKDF2-HMAC-SHA256 iteration count. Higher values are slower but more
/// resistant to brute-force attacks.
const Pbkdf2Iters: u32 = 200_000;

/// Fixed-size header written at the start of every encrypted file.
/// Contains all the metadata needed to derive the key and decrypt the chunks.
const Header = struct {
    /// Magic bytes for format identification.
    magic: [8](u8),
    /// Format version number.
    version: u8,
    /// Plaintext chunk size used during encryption.
    chunk_size: u32,
    /// Random salt for PBKDF2 key derivation.
    salt: [SaltLen]u8,
    /// Random base nonce; per-chunk nonces are derived by XOR-ing a counter.
    base_nonce: [NonceLen]u8,
};

/// Entry point. Parses CLI arguments and dispatches to `encryptFile` or `decryptFile`.
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer {
        const leaked = gpa.deinit();
        std.debug.assert(leaked == .ok);
    }

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var mode: enum { encrypt, decrypt } = undefined;
    var in_path: ?[]const u8 = null;
    var out_path: ?[]const u8 = null;
    var password: ?[]const u8 = null;
    var chunk_size: u32 = ChunkSizeDefault;

    if (args.len < 2) return usage();

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];

        if (std.mem.eql(u8, a, "--encrypt")) {
            mode = .encrypt;
        } else if (std.mem.eql(u8, a, "--decrypt")) {
            mode = .decrypt;
        } else if (std.mem.eql(u8, a, "-i") or std.mem.eql(u8, a, "-in")) {
            i += 1;
            if (i >= args.len) return usage();
            in_path = args[i];
        } else if (std.mem.eql(u8, a, "-o") or std.mem.eql(u8, a, "--out")) {
            i += 1;
            if (i >= args.len) return usage();
            out_path = args[i];
        } else if (std.mem.eql(u8, a, "-p") or std.mem.eql(u8, a, "--password")) {
            i += 1;
            if (i >= args.len) return usage();
            password = args[i];
        } else if (std.mem.eql(u8, a, "--chunk-size")) {
            i += 1;
            if (i >= args.len) return usage();
            chunk_size = try std.fmt.parseInt(u32, args[i], 10);
            if (chunk_size == 0 or chunk_size > MaxChunkSide) {
                return error.InvalidChunkSize;
            }
        } else {
            return usage();
        }
    }

    const in_p = in_path orelse return usage();
    const out_p = out_path orelse return usage();
    const pw = password orelse return usage();

    switch (mode) {
        .encrypt => try encryptFile(allocator, in_p, out_p, pw, chunk_size),
        .decrypt => try decryptFile(allocator, in_p, out_p, pw),
    }
}

/// Encrypts a file using ChaCha20-Poly1305 AEAD.
///
/// 1. Generates a random salt and base nonce.
/// 2. Derives a 256-bit key from `password` via PBKDF2-HMAC-SHA256.
/// 3. Writes a `Header` to `out_path`.
/// 4. Reads `in_path` in `chunk_size`-byte chunks. For each chunk:
///    - Computes a per-chunk nonce from the base nonce and a monotonic counter.
///    - Encrypts and authenticates the chunk (AD = little-endian counter).
///    - Writes: [4-byte LE length][ciphertext][16-byte tag].
fn encryptFile(
    allocator: std.mem.Allocator,
    in_path: []const u8,
    out_path: []const u8,
    password: []const u8,
    chunk_size: u32,
) !void {
    var rng = std.crypto.random;

    var header: Header = undefined;
    header.magic = MAGIC.*;
    header.version = VERSION;
    header.chunk_size = chunk_size;
    rng.bytes(&header.salt);
    rng.bytes(&header.base_nonce);

    var key: [KeyLen]u8 = undefined;
    try deriveKey(&key, password, &header.salt);

    const in_file = try std.fs.cwd().openFile(in_path, .{ .mode = .read_only });
    defer in_file.close();

    const out_file = try std.fs.cwd().createFile(out_path, .{ .read = true });
    defer out_file.close();

    var in_buf = try allocator.alloc(u8, chunk_size);
    defer allocator.free(in_buf);

    var out_buf = try allocator.alloc(u8, chunk_size);
    defer allocator.free(out_buf);

    try out_file.writeAll(std.mem.asBytes(&header));

    var counter: u32 = 0;

    while (true) {
        const n = try in_file.read(in_buf);
        if (n == 0) break;

        const nonce = makeNonce(&header.base_nonce, counter);

        var ad: [4]u8 = undefined;
        std.mem.writeInt(u32, &ad, counter, .little);

        var tag: [TagLen]u8 = undefined;

        std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
            out_buf[0..n],
            &tag,
            in_buf[0..n],
            &ad,
            nonce,
            key,
        );

        var len_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_bytes, @as(u32, @intCast(n)), .little);
        try out_file.writeAll(&len_bytes);
        try out_file.writeAll(out_buf[0..n]);
        try out_file.writeAll(&tag);

        counter += 1;
    }
}

/// Derives a per-chunk nonce by writing the little-endian `counter` into the
/// last 4 bytes of a copy of `base_nonce`. This ensures each chunk is
/// encrypted with a unique nonce while remaining deterministic for decryption.
fn makeNonce(base_nonce: *const [NonceLen]u8, counter: u32) [NonceLen]u8 {
    var nonce = base_nonce.*;
    std.mem.writeInt(u32, nonce[NonceLen - 4 .. NonceLen], counter, .little);
    return nonce;
}

/// Derives a 256-bit symmetric key from `password` and `salt` using
/// PBKDF2-HMAC-SHA256 with `Pbkdf2Iters` iterations.
fn deriveKey(out_key: *[KeyLen]u8, password: []const u8, salt: *[SaltLen]u8) !void {
    try std.crypto.pwhash.pbkdf2(out_key, password, salt, Pbkdf2Iters, std.crypto.auth.hmac.sha2.HmacSha256);
}

/// Decrypts a file previously encrypted by `encryptFile`.
///
/// Reads the header, re-derives the key from the password and stored salt,
/// then processes each chunk by verifying its tag and decrypting.
///
/// **Not yet implemented.**
fn decryptFile(alloctor: std.mem.Allocator, in_path: []const u8, out_path: []const u8, password: []const u8) !void {
    _ = password;

    const in_file = try std.fs.cwd().openFile(in_path, .{ .mode = .read_only });
    defer in_file.close();

    const out_file = try std.fs.cwd().createFile(out_path, .{ .read = true });
    defer out_file.close();

    var header: Header = undefined;
    const header_bytes: []u8 = std.mem.asBytes(&header);
}

/// Prints CLI usage information to stderr and returns `error.InvalidArgs`.
fn usage() void {
    std.debug.print(
        \\Usage:
        \\  zig build-exe aead_filecrypt.zig
        \\  ./aead_filecrypt --encrypt -i <input> -o <output> -p <password> [--chunk 65536]
        \\  ./aead_filecrypt --decrypt -i <input> -o <output> -p <password>
        \\
        \\Format:
        \\  Header (magic+version+chunk_size+salt+base_nonce)
        \\  Repeated chunks:
        \\    u32 little-endian: ciphertext_len
        \\    ciphertext bytes
        \\    16-byte tag
        \\
        \\Security notes:
        \\  - AEAD detects tampering (wrong password or modified file => failure)
        \\  - Uses PBKDF2-HMAC-SHA256 for password -> key (salted)
        \\  - Uses ChaCha20-Poly1305 with per-chunk nonces derived from base_nonce + counter
        \\
    , .{});
}
