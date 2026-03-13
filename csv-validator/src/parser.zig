const std = @import("std");

pub const Row = struct {
    fields: [][]const u8,
};

pub const CsvParser = struct {
    rows: []Row,
};

pub fn parse(csv_bytes: []const u8, allocator: std.mem.Allocator) !CsvParser {
    var rows = try std.ArrayList(Row).initCapacity(allocator, 5);

    var line_iter = std.mem.splitScalar(u8, csv_bytes, '\n');
    while (line_iter.next()) |line| {
        const trimmed = std.mem.trim(u8, line, "\r");
        if (trimmed.len == 0) continue;

        var fields = try std.ArrayList([]const u8).initCapacity(allocator, 5);
        var field_iter = std.mem.splitScalar(u8, trimmed, ',');
        while (field_iter.next()) |field| {
            try fields.append(allocator, field);
        }

        try rows.append(allocator, Row{ .fields = try fields.toOwnedSlice(allocator) });
    }

    return CsvParser{ .rows = try rows.toOwnedSlice(allocator) };
}

test "parse csv" {
    const csv =
        \\name,email,age
        \\Alice,alice@example.com,30
        \\Bob,bob@example.com,25
    ;

    var heap: [64 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&heap);

    const parsed = try parse(csv, fba.allocator());

    try std.testing.expectEqual(@as(usize, 3), parsed.rows.len);
    try std.testing.expectEqualStrings("name", parsed.rows[0].fields[0]);
    try std.testing.expectEqualStrings("Alice", parsed.rows[1].fields[0]);
    try std.testing.expectEqualStrings("bob@example.com", parsed.rows[2].fields[1]);
    try std.testing.expectEqualStrings("25", parsed.rows[2].fields[2]);
}
