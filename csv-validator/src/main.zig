const std = @import("std");
const schema = @import("schema.zig");
const parser = @import("parser.zig");
const validator = @import("validator.zig");

var heap: [2 * 1024 * 1024]u8 align(16) = undefined;
extern const __heap_base: u8;

const builtin = @import("builtin");

pub export fn getHeapBase() usize {
    if (builtin.cpu.arch != .wasm32) return 0;
    const heap_base = @extern(*const u8, .{ .name = "__heap_base" });
    return @intFromPtr(heap_base);
}
export fn validate(
    csv_ptr: [*]const u8,
    csv_len: usize,
    schema_ptr: [*]const u8,
    schema_len: usize,
    out_ptr: [*]u8,
    out_len: usize,
) usize {
    var fba = std.heap.FixedBufferAllocator.init(&heap);
    const allocator = fba.allocator();
    const csv_bytes = csv_ptr[0..csv_len];
    const schema_bytes = schema_ptr[0..schema_len];

    const result = validateInner(
        csv_bytes,
        schema_bytes,
        allocator,
    ) catch {
        const msg = "{\"valid\":false,\"errors\":[{\"row\":0,\"column\":\"\",\"reason\":\"internal error\"}]}";
        const n = @min(msg.len, out_len);
        @memcpy(out_ptr[0..n], msg[0..n]);
        return n;
    };

    // serialize BEFORE resetting allocator - heap memory still valid here
    var out = std.Io.Writer.fixed(out_ptr[0..out_len]);
    std.json.fmt(result, .{}).format(&out) catch {
        const msg = "{\"valid\":false,\"errors\":[{\"row\":0,\"column\":\"fmt_failed\",\"reason\":\"fmt_failed\"}]}";
        const n = @min(msg.len, out_len);
        @memcpy(out_ptr[0..n], msg[0..n]);
        return n;
    };

    return out.end;
}

fn validateInner(
    csv_bytes: []const u8,
    schema_bytes: []const u8,
    allocator: std.mem.Allocator,
) !validator.ValidationResult {
    const parsed_schema = try schema.parse(schema_bytes, allocator);
    const parsed_csv = try parser.parse(csv_bytes, allocator);
    return try validator.validate(parsed_csv, parsed_schema, allocator);
}

test "validate end to end" {
    const csv_bytes =
        \\name,email,age
        \\Alice,not-an-email,30
        \\Bob,bob@example.com,notanumber
    ;
    const schema_bytes =
        \\{
        \\  "columns": [
        \\    { "name": "name",  "type": "string",  "required": true },
        \\    { "name": "email", "type": "email",   "required": true },
        \\    { "name": "age",   "type": "integer", "required": true }
        \\  ]
        \\}
    ;

    var heap_buf: [512 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&heap_buf);
    const allocator = fba.allocator();

    const result = try validateInner(csv_bytes, schema_bytes, allocator);

    try std.testing.expect(!result.valid);
    try std.testing.expectEqual(@as(usize, 2), result.errors.len);
}
