const std = @import("std");

pub fn ToonParser(comptime T: type) type {
    return struct {
        const Self = @This();

        pub fn parse(allocator: std.mem.Allocator, text: []const u8) !T {
            var p = Parser{
                .allocator = allocator,
                .pos = 0,
                .text = text,
                .current_indent = 0,
            };
            const result = try p.parseValue(T, 0);
            return result;
        }

        const Parser = struct {
            allocator: std.mem.Allocator,
            text: []const u8,
            pos: usize,
            current_indent: usize,

            fn parseValue(p: *Parser, comptime Expected: type, indent_level: usize) !Expected {
                const info = @typeInfo(Expected);
                return switch (info) {
                    .int => p.parseNumber(Expected),
                    .float => p.parseFloat(Expected),
                    .bool => p.parseBool(),
                    .pointer => |ptr_info| {
                        //checking if a type is specifically a string slice ([]const u8 or []u8).
                        // .slice == []Expected
                        if (ptr_info.size == .slice and ptr_info.child == u8) {
                            return p.parseString();
                        }
                        @compileError("Unsupported pointer type: " ++ @typeName(Expected));
                    },
                    .@"struct" => |s| p.parseStruct(Expected, s, indent_level),
                    .array => |a| p.parseInlineArray(a.child, a.len),
                    else => @compileError("Unsupported type: " ++ @typeName(Expected)),
                };
            }

            fn parseStruct(p: *Parser, comptime Expected: type, comptime s: std.builtin.Type.Struct, indent_level: usize) !Expected {
                var result: Expected = undefined;
                var seen_fields: usize = 0;

                while (p.pos < p.text.len) {
                    // Check indentation
                    const line_indent = p.peekIndentation();
                    if (line_indent < indent_level) break; // Dedent, done with this struct
                    if (line_indent > indent_level) return error.InvalidIndentation;

                    p.skipIndentation(indent_level);

                    // Parse field name
                    const field_name = try p.parseFieldName();

                    // Find matching struct field
                    var field_found = false;
                    inline for (s.fields, 0..) |field, field_index| {
                        if (std.mem.eql(u8, field_name, field.name)) {
                            if ((seen_fields & (@as(usize, 1) << @intCast(field_index))) != 0) {
                                return error.DuplicateField;
                            }

                            // Check what comes after the field name
                            if (p.peek() == '[') {
                                // Array field
                                @field(result, field.name) = try p.parseArrayField(field.type, indent_level);
                            } else if (p.peek() == ':') {
                                // Simple value or nested struct
                                p.pos += 1; // consume ':'
                                p.skipSpaces();

                                if (p.peek() == '\n' or p.pos >= p.text.len) {
                                    // Nested struct on next lines
                                    p.skipToNextLine();
                                    @field(result, field.name) = try p.parseValue(field.type, indent_level + 2);
                                } else {
                                    // Inline value
                                    @field(result, field.name) = try p.parseValue(field.type, indent_level);
                                    p.skipToNextLine();
                                }
                            } else {
                                return error.UnexpectedCharacter;
                            }

                            seen_fields |= (@as(usize, 1) << @intCast(field_index));
                            field_found = true;
                            break;
                        }
                    }

                    if (!field_found) return error.UnknownField;
                }

                // Check for missing fields
                inline for (s.fields, 0..) |field, i| {
                    if (field.default_value_ptr == null and (seen_fields & (@as(usize, 1) << @intCast(i))) == 0) {
                        return error.MissingField;
                    }
                }

                return result;
            }

            fn parseArrayField(p: *Parser, comptime FieldType: type, indent_level: usize) !FieldType {
                const array_info = @typeInfo(FieldType);
                if (array_info != .array) return error.ExpectedArray;

                // Parse [size]
                try p.expect('[');
                const size = try p.parseArraySize();
                try p.expect(']');

                if (size != array_info.array.len) return error.ArraySizeMismatch;

                const child_type = array_info.array.child;
                const child_info = @typeInfo(child_type);

                // Check if it's an array of structs with schema
                if (child_info == .@"struct" and p.peek() == '{') {
                    // Parse schema: {field1,field2,...}
                    return p.parseTableArray(child_type, array_info.array.len, indent_level);
                } else {
                    // Inline array: value1,value2,value3
                    try p.expect(':');
                    p.skipSpaces();
                    const result = try p.parseInlineArray(child_type, array_info.array.len);
                    p.skipToNextLine();
                    return result;
                }
            }

            fn parseTableArray(p: *Parser, comptime ChildType: type, comptime size: usize, indent_level: usize) ![size]ChildType {
                const child_struct_info = @typeInfo(ChildType).@"struct";

                // Parse schema declaration: {field1,field2,...}
                try p.expect('{');
                var field_order = try std.ArrayList([]const u8).initCapacity(
                    p.allocator,
                    size,
                );
                defer field_order.deinit(p.allocator);

                while (p.peek() != '}') {
                    const field_name = try p.parseIdentifier();
                    try field_order.append(p.allocator, field_name);

                    if (p.peek() == ',') {
                        p.pos += 1;
                    }
                }
                try p.expect('}');
                try p.expect(':');
                p.skipToNextLine();

                var result: [size]ChildType = undefined;

                // Parse rows
                for (0..size) |i| {
                    const row_indent = p.peekIndentation();
                    if (row_indent != indent_level + 2) return error.InvalidIndentation;
                    p.skipIndentation(indent_level + 2);

                    var row: ChildType = undefined;
                    var field_idx: usize = 0;

                    while (field_idx < field_order.items.len) : (field_idx += 1) {
                        const field_name = field_order.items[field_idx];

                        // Find matching struct field
                        var field_found = false;
                        inline for (child_struct_info.fields) |field| {
                            if (std.mem.eql(u8, field_name, field.name)) {
                                @field(row, field.name) = try p.parseValue(field.type, 0);
                                field_found = true;
                                break;
                            }
                        }

                        if (!field_found) return error.UnknownField;

                        // Consume comma if not last field
                        if (field_idx < field_order.items.len - 1) {
                            try p.expect(',');
                        }
                    }

                    result[i] = row;
                    p.skipToNextLine();
                }

                return result;
            }

            fn parseInlineArray(p: *Parser, comptime Child: type, comptime len: usize) ![len]Child {
                var result: [len]Child = undefined;

                for (0..len) |i| {
                    result[i] = try p.parseValue(Child, 0);

                    if (i < len - 1) {
                        try p.expect(',');
                    }
                }

                return result;
            }

            fn parseFieldName(p: *Parser) ![]const u8 {
                return p.parseIdentifier();
            }

            fn parseIdentifier(p: *Parser) ![]const u8 {
                const start = p.pos;

                while (p.pos < p.text.len) {
                    const c = p.text[p.pos];
                    if (std.ascii.isAlphanumeric(c) or c == '_') {
                        p.pos += 1;
                    } else {
                        break;
                    }
                }

                if (start == p.pos) return error.ExpectedIdentifier;
                return p.text[start..p.pos];
            }

            fn parseString(p: *Parser) ![]const u8 {
                const start = p.pos;

                // Parse until comma, newline, or end
                while (p.pos < p.text.len) {
                    const c = p.text[p.pos];
                    if (c == ',' or c == '\n' or c == '\r') break;
                    p.pos += 1;
                }

                var end = p.pos;
                // Trim trailing spaces
                while (end > start and p.text[end - 1] == ' ') {
                    end -= 1;
                }

                return p.text[start..end];
            }

            fn parseNumber(p: *Parser, comptime Expected: type) !Expected {
                const start = p.pos;

                // Handle negative sign
                if (p.peek() == '-') {
                    p.pos += 1;
                }

                // Parse digits
                var has_digits = false;
                while (p.pos < p.text.len and std.ascii.isDigit(p.text[p.pos])) {
                    p.pos += 1;
                    has_digits = true;
                }

                if (!has_digits) {
                    p.pos = start;
                    return error.InvalidNumber;
                }

                const slice = p.text[start..p.pos];
                return std.fmt.parseInt(Expected, slice, 10) catch return error.InvalidNumber;
            }

            fn parseFloat(p: *Parser, comptime Expected: type) !Expected {
                const start = p.pos;
                var end = p.pos;

                // Handle sign
                if (end < p.text.len and (p.text[end] == '-' or p.text[end] == '+')) {
                    end += 1;
                }

                // Parse number
                while (end < p.text.len and (std.ascii.isDigit(p.text[end]) or p.text[end] == '.')) {
                    end += 1;
                }

                if (start == end) return error.InvalidFloat;

                const slice = p.text[start..end];
                const value = std.fmt.parseFloat(Expected, slice) catch return error.InvalidFloat;
                p.pos = end;

                return value;
            }

            fn parseBool(p: *Parser) !bool {
                if (p.remaining() >= 4 and std.mem.eql(u8, p.text[p.pos .. p.pos + 4], "true")) {
                    p.pos += 4;
                    return true;
                }

                if (p.remaining() >= 5 and std.mem.eql(u8, p.text[p.pos .. p.pos + 5], "false")) {
                    p.pos += 5;
                    return false;
                }

                return error.InvalidBoolean;
            }

            fn parseArraySize(p: *Parser) !usize {
                const start = p.pos;

                while (p.pos < p.text.len and std.ascii.isDigit(p.text[p.pos])) {
                    p.pos += 1;
                }

                if (start == p.pos) return error.ExpectedNumber;

                const slice = p.text[start..p.pos];
                return std.fmt.parseInt(usize, slice, 10) catch return error.InvalidNumber;
            }

            fn peekIndentation(p: *Parser) usize {
                var indent: usize = 0;
                var i = p.pos;

                while (i < p.text.len and p.text[i] == ' ') {
                    indent += 1;
                    i += 1;
                }

                return indent;
            }

            fn skipIndentation(p: *Parser, expected: usize) void {
                var count: usize = 0;
                while (count < expected and p.pos < p.text.len and p.text[p.pos] == ' ') {
                    p.pos += 1;
                    count += 1;
                }
            }

            fn skipSpaces(p: *Parser) void {
                while (p.pos < p.text.len and p.text[p.pos] == ' ') {
                    p.pos += 1;
                }
            }

            fn skipToNextLine(p: *Parser) void {
                while (p.pos < p.text.len) {
                    if (p.text[p.pos] == '\n') {
                        p.pos += 1;
                        break;
                    }
                    p.pos += 1;
                }
            }

            fn peek(p: *Parser) ?u8 {
                if (p.pos >= p.text.len) return null;
                return p.text[p.pos];
            }

            fn remaining(p: *Parser) usize {
                if (p.pos >= p.text.len) return 0;
                return p.text.len - p.pos;
            }

            fn expect(p: *Parser, char: u8) !void {
                if (p.pos >= p.text.len or p.text[p.pos] != char) {
                    return error.UnexpectedCharacter;
                }
                p.pos += 1;
            }
        };
    };
}

// Test will use the example provide in https://github.com/toon-format/spec
test "parse TOON hikes example" {
    const allocator = std.testing.allocator;

    const Context = struct {
        task: []const u8,
        location: []const u8,
        season: []const u8,
    };

    const Hike = struct {
        id: u32,
        name: []const u8,
        distanceKm: f32,
        elevationGain: u32,
        companion: []const u8,
        wasSunny: bool,
    };

    const HikesData = struct {
        context: Context,
        friends: [3][]const u8,
        hikes: [3]Hike,
    };

    const input =
        \\context:
        \\  task: Our favorite hikes together
        \\  location: Boulder
        \\  season: spring_2025
        \\friends[3]: ana,luis,sam
        \\hikes[3]{id,name,distanceKm,elevationGain,companion,wasSunny}:
        \\  1,Blue Lake Trail,7.5,320,ana,true
        \\  2,Ridge Overlook,9.2,540,luis,false
        \\  3,Wildflower Loop,5.1,180,sam,true
    ;

    const result = try ToonParser(HikesData).parse(allocator, input);
    std.debug.print("TOON parse : {any}", .{result});

    try std.testing.expectEqualStrings("Our favorite hikes together", result.context.task);
    try std.testing.expectEqualStrings("Boulder", result.context.location);
    try std.testing.expectEqualStrings("spring_2025", result.context.season);

    try std.testing.expectEqualStrings("ana", result.friends[0]);
    try std.testing.expectEqualStrings("luis", result.friends[1]);
    try std.testing.expectEqualStrings("sam", result.friends[2]);

    try std.testing.expectEqual(@as(u32, 1), result.hikes[0].id);
    try std.testing.expectEqualStrings("Blue Lake Trail", result.hikes[0].name);
    try std.testing.expectEqual(@as(f32, 7.5), result.hikes[0].distanceKm);
    try std.testing.expectEqual(@as(u32, 320), result.hikes[0].elevationGain);
    try std.testing.expectEqualStrings("ana", result.hikes[0].companion);
    try std.testing.expectEqual(true, result.hikes[0].wasSunny);

    try std.testing.expectEqual(@as(u32, 2), result.hikes[1].id);
    try std.testing.expectEqual(false, result.hikes[1].wasSunny);
}
