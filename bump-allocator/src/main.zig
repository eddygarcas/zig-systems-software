const std = @import("std");

pub const BumpAllocator = struct {
    buffer: []align(std.heap.page_size_max) u8,
    pos: std.atomic.Value(usize),

    pub fn init(buffer: []align(std.heap.page_size_max) u8) BumpAllocator {
        return .{
            .buffer = buffer,
            .pos = std.atomic.Value(usize).init(0),
        };
    }

    pub const vtable = std.mem.Allocator.VTable{
        .alloc = alloc,
        .resize = resize,
        .free = free,
        .remap = remap,
    };

    pub fn allocator(self: *BumpAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    fn remap(ctx: *anyopaque, buf: []u8, ptr_align: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        _ = ret_addr;
        _ = ptr_align; // existing buf already satisfies its alignment

        const self: *BumpAllocator = @ptrCast(@alignCast(ctx));

        const base = @intFromPtr(self.buffer.ptr);
        const start = @intFromPtr(buf.ptr);

        // Must be inside our backing buffer
        if (start < base or start > base + self.buffer.len) return null;

        const start_off: usize = start - base;
        const old_end_off: usize = start_off + buf.len;

        while (true) {
            const end = self.pos.load(.monotonic);

            // Only remap if `buf` is the last allocation
            if (old_end_off != end) return null;

            const new_end_off = start_off + new_len;

            // If growing, must fit in the backing buffer
            if (new_end_off > self.buffer.len) return null;

            // Attempt to update the bump pointer (works for shrink or grow)
            const exchanged = self.pos.cmpxchgWeak(
                end,
                new_end_off,
                .monotonic,
                .monotonic,
            );

            if (exchanged == null) {
                // success, pointer stays the same
                return buf.ptr;
            }

            // CAS failed => someone changed `pos`, retry
        }
    }

    fn alloc(
        ctx: *anyopaque,
        len: usize,
        ptr_align: std.mem.Alignment,
        ret_addr: usize,
    ) ?[*]u8 {
        _ = ret_addr;
        const self: *BumpAllocator = @ptrCast(@alignCast(ctx));

        var current = self.pos.load(.monotonic);

        while (true) {
            const aligned_start = std.mem.alignForward(usize, current, ptr_align.toByteUnits());
            const next = aligned_start + len;

            const exchanged = self.pos.cmpxchgWeak(
                current,
                next,
                .monotonic,
                .monotonic,
            ) orelse {
                return self.buffer.ptr + aligned_start;
            };
            current = exchanged;
        }
    }

    fn resize(
        ctx: *anyopaque,
        buf: []u8,
        old_align: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) bool {
        _ = old_align;
        _ = ret_addr;

        const self: *BumpAllocator = @ptrCast(@alignCast(ctx));
        const end = self.pos.load(.monotonic);

        return (buf.ptr + buf.len == self.buffer.ptr + end) and new_len <= buf.len;
    }

    fn free(
        ctx: *anyopaque,
        buf: []u8,
        old_align: std.mem.Alignment,
        ret_addr: usize,
    ) void {
        _ = ctx;
        _ = buf;
        _ = old_align;
        _ = ret_addr;
    }

    fn reset(self: *BumpAllocator) void {
        self.pos.store(0, .monotonic);
    }
};

pub fn main() !void {
    var backing: [10 * 1024 * 1024]u8 align(std.heap.page_size_max) = undefined;
    var bump = BumpAllocator.init(backing[0..]);
    const alloc = bump.allocator();

    const a = try alloc.alloc(u64, 1_000_000);
    _ = a;

    bump.reset();
}
