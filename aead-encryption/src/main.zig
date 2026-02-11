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
/// Do not use packed strct with arrays
const Header = extern struct {
    /// Magic bytes for format identification.
    magic: [8](u8),
    /// Format version number.
    version: u8,

    _pad: [3]u8 = [_]u8{0} ** 3, // explicit zero-filled padding
    /// Plaintext chunk size used during encryption.
    chunk_size: u32,
    /// Random salt for PBKDF2 key derivation.
    salt: [SaltLen]u8,
    /// Random base nonce; per-chunk nonces are derived by XOR-ing a counter.
    base_nonce: [NonceLen]u8,
};

/// Entry point. Parses CLI arguments and dispatches to `encryptFile` or `decryptFile`.
pub fn main(init: std.process.Init) !void {
    //var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    //const allocator = gpa.allocator();
    //defer {
    //    const leaked = gpa.deinit();
    //    std.debug.assert(leaked == .ok);
    //}

    //const args = try std.process.argsAlloc(allocator);
    //defer std.process.argsFree(allocator, args);
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

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
        .encrypt => try encryptFile(
            allocator,
            in_p,
            out_p,
            pw,
            chunk_size,
            init.io,
        ),
        .decrypt => try decryptFile(
            allocator,
            in_p,
            out_p,
            pw,
            init.io,
        ),
    }
    std.debug.print("\x1b[32mDone!\x1b[0m", .{});
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
    io: std.Io,
) !void {
    //var rng = std.crypto.random;

    var header: Header = undefined;
    header.magic = MAGIC.*;
    header.version = VERSION;
    header.chunk_size = chunk_size;
    //rng.bytes(&header.salt);
    //rng.bytes(&header.base_nonce);

    std.Io.random(io, &header.salt);
    std.Io.random(io, &header.base_nonce);

    var key: [KeyLen]u8 = undefined;
    try deriveKey(&key, password, &header.salt);

    const in_file = try std.Io.Dir.cwd().openFile(io, in_path, .{ .mode = .read_only });
    defer in_file.close(io);

    const out_file = try std.Io.Dir.cwd().createFile(io, out_path, .{ .read = true });
    defer out_file.close(io);

    var in_buf = try allocator.alloc(u8, chunk_size);
    defer allocator.free(in_buf);

    var out_buf = try allocator.alloc(u8, chunk_size);
    defer allocator.free(out_buf);

    const writer_buffer = try allocator.alloc(u8, 4096); // Separate buffer for writer
    defer allocator.free(writer_buffer);

    var writer_inst = out_file.writer(io, writer_buffer); // Use separate buffer
    const writer = &writer_inst.interface;
    try writer.writeAll(std.mem.asBytes(&header));
    //try writer.flush(); // Yes, flush after header too!

    var reader_inst = in_file.reader(io, in_buf);
    const reader = &reader_inst.interface;

    var counter: u32 = 0;

    while (true) {
        const n = try reader.readSliceShort(in_buf);
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
        try writer.writeAll(&len_bytes);
        try writer.writeAll(out_buf[0..n]);
        try writer.writeAll(&tag);

        counter += 1;
    }
    try writer.flush();
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
/// 1. Reads and validates the `Header` from `in_path` (magic bytes and version).
/// 2. Re-derives the 256-bit key from `password` via PBKDF2-HMAC-SHA256 using
///    the salt stored in the header.
/// 3. Processes each chunk sequentially:
///    - Reads the 4-byte little-endian ciphertext length.
///    - Reads the ciphertext and 16-byte Poly1305 authentication tag.
///    - Computes the per-chunk nonce from the base nonce and counter.
///    - Verifies the tag and decrypts (AD = little-endian counter).
///    - Writes the plaintext to `out_path`.
///
/// Returns `error.UnsupportedFormat` if the magic bytes or version mismatch.
/// Returns `error.CorruptLenght` if a chunk length exceeds the header's chunk size.
/// Returns `error.Truncated` if the file ends mid-chunk.
/// Decryption fails with `error.AuthenticationFailed` if any tag is invalid
/// (wrong password, corrupted data, or tampered ciphertext).
fn decryptFile(
    allocator: std.mem.Allocator,
    in_path: []const u8,
    out_path: []const u8,
    password: []const u8,
    io: std.Io,
) !void {
    const in_file = try std.Io.Dir.cwd().openFile(io, in_path, .{ .mode = .read_only });
    defer in_file.close(io);

    const out_file = try std.Io.Dir.cwd().createFile(io, out_path, .{ .read = true });
    defer out_file.close(io);

    // Allocate buffer big enough for header AND chunks
    const read_buffer = try allocator.alloc(u8, @max(@sizeOf(Header), 65536));
    defer {
        @memset(read_buffer, 0); // Zero sensitive data before freeing
        allocator.free(read_buffer);
    }

    // Create ONE reader for the entire file
    var reader_inst = in_file.reader(io, read_buffer);
    const reader = &reader_inst.interface;

    // Read header using the reader
    var header: Header = undefined;
    try reader.readSliceAll(std.mem.asBytes(&header));

    if (!std.mem.eql(u8, &header.magic, MAGIC) or header.version != VERSION) {
        return error.UnsupportedFormat;
    }

    if (!std.mem.eql(u8, &header.magic, MAGIC) or header.version != VERSION) {
        return error.UnsupportedFormat;
    }

    var key: [KeyLen]u8 = undefined;
    try deriveKey(&key, password, &header.salt);

    var in_buf = try allocator.alloc(u8, header.chunk_size);
    defer allocator.free(in_buf);

    var out_buf = try allocator.alloc(u8, header.chunk_size);
    defer allocator.free(out_buf);

    const writer_buffer = try allocator.alloc(u8, 4096);
    defer allocator.free(writer_buffer);
    var writer_inst = out_file.writer(io, writer_buffer);
    const writer = &writer_inst.interface;

    var counter: u32 = 0;

    while (true) {
        var len_bytes: [4]u8 = undefined;
        const len_read = reader.readSliceShort(&len_bytes) catch |err| switch (err) {
            //error.EndOfStream => 0,
            else => return err,
        };
        if (len_read == 0) break;
        if (len_read != 4) break;

        const ct_len = std.mem.readInt(u32, &len_bytes, .little);
        if (ct_len > header.chunk_size) return error.CorruptLenght;

        //try reader.readSliceAll(in_buf[0..ct_len]);
        const n_ct = try reader.readSliceShort(in_buf[0..ct_len]);
        if (n_ct != ct_len) return error.Truncated;

        var tag: [TagLen]u8 = undefined;
        const n_tag = try reader.readSliceShort(&tag);
        if (n_tag != TagLen) return error.Truncated;

        const nonce = makeNonce(&header.base_nonce, counter);

        var ad: [4]u8 = undefined;
        std.mem.writeInt(u32, &ad, counter, .little);

        try std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
            out_buf[0..ct_len],
            in_buf[0..ct_len],
            tag,
            &ad,
            nonce,
            key,
        );

        try writer.writeAll(out_buf[0..ct_len]);

        counter += 1;
    }
    try writer.flush();
}

/// Prints CLI usage information to stderr and returns `error.InvalidArgs`.
fn usage() void {
    std.debug.print(
        \\Usage:
        \\  zig build-exe aead-crypt.zig
        \\  ./aead-crypt --encrypt -i <input> -o <output> -p <password> [--chunk-size 65536]
        \\  ./aead-crypt --decrypt -i <input> -o <output> -p <password>
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

test "encrypt and decrypt round-trip" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create a test init with IO
    //var init = std.process.Init;
    const io = std.testing.io;

    // Test data
    const plaintext = "This is a secret message for testing encryption!";
    const password = "test_password_123";
    const test_file = "test_plain.txt";
    const encrypted_file = "test_encrypted.bin";
    const decrypted_file = "test_decrypted.txt";

    // Cleanup any leftover files
    std.Io.Dir.cwd().deleteFile(io, test_file) catch {};
    std.Io.Dir.cwd().deleteFile(io, encrypted_file) catch {};
    std.Io.Dir.cwd().deleteFile(io, decrypted_file) catch {};
    defer {
        std.Io.Dir.cwd().deleteFile(io, test_file) catch {};
        std.Io.Dir.cwd().deleteFile(io, encrypted_file) catch {};
        std.Io.Dir.cwd().deleteFile(io, decrypted_file) catch {};
    }

    // Write test plaintext
    {
        const file = try std.Io.Dir.cwd().createFile(io, test_file, .{});
        defer file.close(io);

        const writer_buffer = try allocator.alloc(u8, 4096);
        defer allocator.free(writer_buffer);
        var writer_inst = file.writer(io, writer_buffer);
        const writer = &writer_inst.interface;

        try writer.writeAll(plaintext);
        try writer.flush();
    }

    // Encrypt
    try encryptFile(
        allocator,
        test_file,
        encrypted_file,
        password,
        1024, // Small chunk size for testing
        io,
    );

    // Verify encrypted file exists and is different
    {
        const enc_file = try std.Io.Dir.cwd().openFile(io, encrypted_file, .{});
        defer enc_file.close(io);
        const stat = try enc_file.stat(io);

        try testing.expect(stat.size > @sizeOf(Header)); // At least header + some data
    }

    // Decrypt
    try decryptFile(
        allocator,
        encrypted_file,
        decrypted_file,
        password,
        io,
    );

    // Verify decrypted matches original
    {
        const dec_file = try std.Io.Dir.cwd().openFile(io, decrypted_file, .{});
        defer dec_file.close(io);
        const read_buffer = try allocator.alloc(u8, plaintext.len);
        defer allocator.free(read_buffer);
        var reader_inst = dec_file.reader(io, read_buffer);
        const reader = &reader_inst.interface;
        try reader.readSliceAll(read_buffer);
        try testing.expectEqualStrings(plaintext, read_buffer);
    }
}

test "decrypt with wrong password fails" {
    const testing = std.testing;
    const allocator = testing.allocator;

    //var init = std.process.init;
    const io = std.testing.io;

    const plaintext = "Secret data";
    const correct_password = "correct123";
    const wrong_password = "wrong456";
    const test_file = "test_pw_plain.txt";
    const encrypted_file = "test_pw_encrypted.bin";
    const decrypted_file = "test_pw_decrypted.txt";

    defer {
        std.Io.Dir.cwd().deleteFile(io, test_file) catch {};
        std.Io.Dir.cwd().deleteFile(io, encrypted_file) catch {};
        std.Io.Dir.cwd().deleteFile(io, decrypted_file) catch {};
    }

    // Create and encrypt
    {
        const file = try std.Io.Dir.cwd().createFile(io, test_file, .{});
        defer file.close(io);

        const writer_buffer = try allocator.alloc(u8, 4096);
        defer allocator.free(writer_buffer);
        var writer_inst = file.writer(io, writer_buffer);
        const writer = &writer_inst.interface;

        try writer.writeAll(plaintext);
        try writer.flush();
    }
    try encryptFile(
        allocator,
        test_file,
        encrypted_file,
        correct_password,
        1024,
        io,
    );

    try testing.expectError(error.AuthenticationFailed, decryptFile(
        allocator,
        encrypted_file,
        decrypted_file,
        wrong_password,
        io,
    ));
}
