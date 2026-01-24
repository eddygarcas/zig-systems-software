//! XOR Encryption/Decryption Utility
//!
//! A simple command-line tool that encrypts or decrypts files using XOR cipher.
//! XOR encryption is a basic symmetric cipher where the same key is used for both
//! encryption and decryption. While simple to implement, it provides minimal security
//! and should only be used for educational purposes.
//!
//! Usage: xorfer --encrypt | --decrypt <input> <output> <key>
//!
//! Note: XOR cipher is vulnerable to frequency analysis and known-plaintext attacks.
//! Do NOT use this for securing sensitive data in production environments.

const std = @import("std");

/// Main entry point for the XOR encryption/decryption utility.
/// Handles command-line argument parsing, file I/O, and XOR cipher operations.
///
/// Returns an error if:
/// - Memory allocation fails
/// - File reading/writing fails
/// - Command-line arguments are invalid or missing
pub fn main() !void {
    // Initialize a General Purpose Allocator for dynamic memory management.
    // This allocator provides safety checks and can detect memory leaks.
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();

    // Ensure the allocator is properly deinitialized when the function exits.
    // The assertion checks that no memory leaks occurred during execution.
    defer {
        const leaked = gpa.deinit();
        std.debug.assert(leaked == .ok);
    }

    // Parse command-line arguments
    var args = std.process.args();

    // Skip the first argument (program name)
    _ = args.skip();

    // Get the mode argument (--encrypt or --decrypt)
    // If not provided, print usage instructions and exit
    const mode = args.next() orelse {
        std.debug.print("Usage: xorfer --encrypt | --decrypt <input> <output> <key>\n", .{});
        return;
    };

    // Get the input file path
    // This is the file that will be encrypted or decrypted
    const input_path = args.next() orelse {
        std.debug.print("Missing input file.\n", .{});
        return;
    };

    // Get the output file path
    // The encrypted/decrypted result will be written here
    const output_path = args.next() orelse {
        std.debug.print("Missing output file.\n", .{});
        return;
    };

    // Get the encryption/decryption key
    // This key is used to XOR each byte of the input file
    const key = args.next() orelse {
        std.debug.print("Missing key.\n", .{});
        return;
    };

    // Set a file size limit of 10 MB to prevent excessive memory allocation.
    // This protects against attempting to load extremely large files into memory.
    const limit: std.Io.Limit = .limited(10 * 1024 * 1024);

    // Read the entire input file into memory.
    // The file data is allocated on the heap and must be freed later.
    const file_data = try std.fs.cwd().readFileAlloc(input_path, alloc, limit);
    defer alloc.free(file_data);

    // Allocate output buffer with the same size as the input.
    // XOR cipher produces output of the same length as the input.
    var output = try alloc.alloc(u8, file_data.len);
    defer alloc.free(output);

    // XOR Cipher Implementation
    //
    // The XOR cipher is the simplest form of encryption. It works by applying
    // the XOR (exclusive OR) operation between each byte of the plaintext and
    // the corresponding byte of the key.
    //
    // Properties:
    // - Symmetric: Same operation for encryption and decryption
    // - Reversible: Applying XOR twice with the same key returns the original data
    // - Key reuse: The key is repeated cyclically using modulo operation
    //
    // Security concerns:
    // - Very easy to decrypt without the key using frequency analysis
    // - Vulnerable to known-plaintext attacks
    // - Pattern repetition reveals key length
    // - This is for LEARNING PURPOSES ONLY
    //
    // Algorithm:
    // For each byte at position i:
    //   output[i] = input[i] XOR key[i % key_length]
    //
    // The modulo operation (%) ensures that if the key is shorter than the input,
    // it wraps around and repeats from the beginning.
    for (file_data, 0..) |byte, i| {
        output[i] = byte ^ key[i % key.len];
    }

    // Write the encrypted/decrypted data to the output file.
    // This overwrites the file if it already exists.
    try std.fs.cwd().writeFile(.{
        .sub_path = output_path,
        .data = output,
        .flags = .{},
    });

    // Print success message indicating whether encryption or decryption was performed
    std.debug.print("{s} completed -> {s}\n", .{ if (std.mem.eql(u8, mode, "--encrypt")) "Encryption" else "Decryption", output_path });
}
