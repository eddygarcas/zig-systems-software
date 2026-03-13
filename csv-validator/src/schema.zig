const std = @import("std");

pub const ColumnType = enum {
    string,
    integer,
    email,
};

pub const Column = struct {
    name: []const u8,
    column_type: ColumnType,
    required: bool,
};

pub const Schema = struct {
    columns: []Column,
};

pub fn parse(json_bytes: []const u8, allocator: std.mem.Allocator) !Schema {
    const parsed = try std.json.parseFromSlice(
        struct {
            columns: []struct {
                name: []const u8,
                type: []const u8,
                required: bool,
            },
        },
        allocator,
        json_bytes,
        .{},
    );

    var columns = try allocator.alloc(Column, parsed.value.columns.len);

    for (parsed.value.columns, 0..) |col, i| {
        const col_type = if (std.mem.eql(u8, col.type, "integer"))
            ColumnType.integer
        else if (std.mem.eql(u8, col.type, "email"))
            ColumnType.email
        else
            ColumnType.string;

        columns[i] = Column{
            .name = col.name,
            .column_type = col_type,
            .required = col.required,
        };
    }

    return Schema{ .columns = columns };
}

test "parse schema" {
    const json =
        \\{
        \\  "columns": [
        \\    { "name": "email", "type": "email", "required": true },
        \\    { "name": "age", "type": "integer", "required": true },
        \\    { "name": "name", "type": "string", "required": false }
        \\  ]
        \\}
    ;

    var heap: [64 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&heap);

    const parsed = try parse(json, fba.allocator());

    try std.testing.expectEqual(@as(usize, 3), parsed.columns.len);
    try std.testing.expectEqualStrings("email", parsed.columns[0].name);
    try std.testing.expectEqual(ColumnType.email, parsed.columns[0].column_type);
    try std.testing.expectEqual(true, parsed.columns[0].required);
    try std.testing.expectEqual(ColumnType.integer, parsed.columns[1].column_type);
    try std.testing.expectEqual(ColumnType.string, parsed.columns[2].column_type);
    try std.testing.expectEqual(false, parsed.columns[2].required);
}
