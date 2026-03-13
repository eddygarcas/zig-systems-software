const std = @import("std");
const schema = @import("schema.zig");
const parser = @import("parser.zig");

pub const ValidationError = struct {
    row: usize,
    column: []const u8,
    reason: []const u8,
};

pub const ValidationResult = struct {
    valid: bool,
    errors: []ValidationError,
};

pub fn validate(
    csv: parser.CsvParser,
    s: schema.Schema,
    allocator: std.mem.Allocator,
) !ValidationResult {
    var errors = try std.ArrayList(ValidationError).initCapacity(allocator, 5);

    if (csv.rows.len == 0) {
        return ValidationResult{ .valid = false, .errors = &.{} };
    }

    // first row is the header
    const header = csv.rows[0];

    // validate header columns match schema
    for (s.columns, 0..) |col, i| {
        if (i >= header.fields.len) {
            try errors.append(allocator, .{
                .row = 0,
                .column = col.name,
                .reason = "missing column in header",
            });
            continue;
        }
        if (!std.mem.eql(u8, header.fields[i], col.name)) {
            try errors.append(allocator, .{
                .row = 0,
                .column = col.name,
                .reason = "column name mismatch",
            });
        }
    }

    // validate each data row
    for (csv.rows[1..], 1..) |row, row_idx| {
        for (s.columns, 0..) |col, col_idx| {
            if (col_idx >= row.fields.len) {
                try errors.append(allocator, .{
                    .row = row_idx,
                    .column = col.name,
                    .reason = "missing field",
                });
                continue;
            }

            const field = row.fields[col_idx];

            // required check
            if (col.required and field.len == 0) {
                try errors.append(allocator, .{
                    .row = row_idx,
                    .column = col.name,
                    .reason = "field is required",
                });
                continue;
            }

            // type check
            switch (col.column_type) {
                .integer => {
                    _ = std.fmt.parseInt(i64, field, 10) catch {
                        try errors.append(allocator, .{
                            .row = row_idx,
                            .column = col.name,
                            .reason = "must be an integer",
                        });
                    };
                },
                .email => {
                    if (std.mem.indexOf(u8, field, "@") == null) {
                        try errors.append(allocator, .{
                            .row = row_idx,
                            .column = col.name,
                            .reason = "invalid email format",
                        });
                    }
                },
                .string => {},
            }
        }
    }

    const err_slice = try errors.toOwnedSlice(allocator);
    return ValidationResult{
        .valid = err_slice.len == 0,
        .errors = err_slice,
    };
}

test "valid csv" {
    const csv_bytes =
        \\name,email,age
        \\Alice,alice@example.com,30
        \\Bob,bob@example.com,25
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

    var heap: [128 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&heap);
    const alloc = fba.allocator();

    const parsed_csv = try parser.parse(csv_bytes, alloc);
    const parsed_schema = try schema.parse(schema_bytes, alloc);
    const result = try validate(parsed_csv, parsed_schema, alloc);

    try std.testing.expect(result.valid);
    try std.testing.expectEqual(@as(usize, 0), result.errors.len);
}

test "invalid csv" {
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

    var heap: [128 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&heap);
    const alloc = fba.allocator();

    const parsed_csv = try parser.parse(csv_bytes, alloc);
    const parsed_schema = try schema.parse(schema_bytes, alloc);
    const result = try validate(parsed_csv, parsed_schema, alloc);

    try std.testing.expect(!result.valid);
    try std.testing.expectEqual(@as(usize, 2), result.errors.len);
    try std.testing.expectEqualStrings("invalid email format", result.errors[0].reason);
    try std.testing.expectEqualStrings("must be an integer", result.errors[1].reason);
}
