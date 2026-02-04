const std = @import("std");

pub fn JsonParser(comptime T: type) type {
    return struct {
        const Self = @This();

        pub fn parse(text: []const u8) !T {
            var p = Parser{
                .pos = 0,
                .text = text,
            };
            const result = try p.parseValue(T);
            p.skipWhiteSpace();
            if (p.pos != text.len) return error.ExtraData;
            return result;
        }

        const Parser = struct {
            text: []const u8,
            pos: usize,

            fn skipWhiteSpace(p: *Parser) void {
                while (p.pos < p.text.len and std.ascii.isWhitespace(p.text[p.pos])) : (p.pos += 1) {
                    //std.debug.print("Skip whitespace pos: {d}\r", .{p.pos});
                }
            }

            fn parseValue(p: *Parser, comptime Expected: type) !Expected {
                p.skipWhiteSpace();
                if (p.pos >= p.text.len) return error.UnexpectedEndOfInput;

                const info = @typeInfo(Expected);
                std.debug.print("Type: {s}\n", .{@typeName(Expected)});
                return switch (info) {
                    .int => p.parseInt(Expected),
                    .float => p.parseFloat(Expected),
                    .bool => p.parseBool(),
                    .pointer => p.parseString(),
                    .optional => |opt| p.parseOptional(opt),
                    .@"struct" => |s| p.parseStruct(Expected, s),
                    .array => |a| p.parseArray(a.child, a.len),
                    .void => {
                        try p.expect('{');
                        try p.expect('}');
                        return {};
                    },
                    else => @compileError("Unsupported type: " ++ @typeName(Expected)),
                };
            }

            // Will use bitwise operators to keep track of seen fields rather than using hashmaps or arrays which
            // implies using allocators that we don't want.
            fn parseStruct(p: *Parser, comptime Expected: type, comptime s: std.builtin.Type.Struct) !Expected {
                try p.expect('{');
                var result: Expected = undefined;
                var seen_fields: usize = 0;

                // This works - iterating at comptime
                while (true) {
                    p.skipWhiteSpace();
                    if (p.peek() == '}') break;

                    const key = try p.parseString();
                    try p.expect(':');
                    inline for (s.fields, 0..) |field, field_index| {
                        std.debug.print("Field: {s}\n", .{field.name});
                        if (std.mem.eql(u8, key, field.name)) {
                            if ((seen_fields & (@as(usize, 1) << @intCast(field_index))) != 0) return error.DuplicateField;
                            @field(result, field.name) = try p.parseValue(field.type);
                            seen_fields |= (@as(usize, 1) << @intCast(field_index));
                            break;
                        }
                    } else {
                        return error.UnkownField;
                    }
                    p.skipWhiteSpace();
                    if (p.consume(',') == null) break;
                }
                try p.expect('}');

                inline for (s.fields, 0..) |field, i| {
                    if (field.default_value_ptr == null and (seen_fields & (@as(usize, 1) << @intCast(i))) == 0) {
                        return error.MissingField;
                    }
                }

                return result;
            }

            fn parseInt(p: *Parser, comptime Expected: type) !Expected {
                const start = p.pos;

                // Handle optional negative sign
                const is_negative = if (p.peek() == '-') blk: {
                    p.pos += 1;
                    break :blk true;
                } else false;

                // Parse digits
                var value: Expected = 0;
                var has_digits = false;

                while (p.pos < p.text.len and std.ascii.isDigit(p.text[p.pos])) {
                    const digit = p.text[p.pos] - '0';
                    value = try std.math.mul(Expected, value, 10);
                    value = try std.math.add(Expected, value, digit);
                    p.pos += 1;
                    has_digits = true;
                }

                if (!has_digits) {
                    p.pos = start;
                    return error.InvalidNumber;
                }

                if (is_negative) {
                    value = try std.math.negate(value);
                }

                return value;
            }

            fn parseFloat(p: *Parser, comptime Expected: type) !T {
                const start = p.pos;
                var end = p.pos;

                // Find the end of the number (sign, digits, decimal point, exponent)
                if (end < p.text.len and (p.text[end] == '-' or p.text[end] == '+')) {
                    end += 1;
                }

                while (end < p.text.len and (std.ascii.isDigit(p.text[end]) or
                    p.text[end] == '.' or p.text[end] == 'e' or p.text[end] == 'E' or
                    p.text[end] == '-' or p.text[end] == '+'))
                {
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

            fn parseString(p: *Parser) ![]const u8 {
                try p.expect('"');

                const start = p.pos;
                var end = start;

                while (end < p.text.len) {
                    if (p.text[end] == '"') {
                        const result = p.text[start..end];
                        p.pos = end + 1;
                        return result;
                    }

                    // Handle escaped characters
                    if (p.text[end] == '\\') {
                        end += 2; // Skip the backslash and next char
                    } else {
                        end += 1;
                    }
                }

                return error.UnterminatedString;
            }

            fn parseOptional(p: *Parser, comptime Child: type) !?Child {
                p.skipWhitespace();

                // Check for null
                if (p.remaining() >= 4 and std.mem.eql(u8, p.text[p.pos .. p.pos + 4], "null")) {
                    p.pos += 4;
                    return null;
                }

                // Otherwise parse as the child type
                return try p.parseValue(Child);
            }

            fn parseArray(p: *Parser, comptime Child: type, comptime len: usize) ![len]Child {
                try p.expect('[');
                p.skipWhitespace();

                var result: [len]Child = undefined;
                var i: usize = 0;

                while (i < len) : (i += 1) {
                    if (i > 0) {
                        try p.expect(',');
                        p.skipWhitespace();
                    }

                    result[i] = try p.parseValue(Child);
                    p.skipWhitespace();
                }

                try p.expect(']');
                return result;
            }
            // Helper methods you'll likely need:

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

            fn consume(p: *Parser, char: u8) ?u8 {
                if (p.pos >= p.text.len or p.text[p.pos] != char) {
                    return null;
                }
                p.pos += 1;
                return char;
            }
        };
    };
}

pub fn main() !void {}

test "parse simple struct" {
    const User = struct {
        id: u32,
        name: []const u8,
        admin: bool,
    };

    const input =
        \\      {    "id": 12345,     "name": "Alice", "admin": true }
    ;

    const result = try JsonParser(User).parse(input);

    std.debug.print("Parse user:\n id: {d}\n name: {s}\n admin: {any}\n", .{ result.id, result.name, result.admin });
    try std.testing.expectEqual(@as(u32, 12345), result.id);
    try std.testing.expectEqualStrings("Alice", result.name);
    try std.testing.expectEqual(true, result.admin);
}
