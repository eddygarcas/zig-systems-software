//! Bump Allocator Implementation
//!
//! A bump allocator (also known as an arena allocator or linear allocator) is one of the
//! simplest and fastest memory allocation strategies. It maintains a pointer (the "bump pointer")
//! that starts at the beginning of a pre-allocated buffer and moves forward with each allocation.
//!
//! Key characteristics:
//! - Extremely fast allocation: O(1) with minimal overhead
//! - No individual deallocation: free() is a no-op
//! - Memory is reclaimed in bulk via reset()
//! - Thread-safe implementation using atomic operations
//! - Ideal for temporary allocations or phase-based memory management
//!
//! Use cases:
//! - Request handling in servers (allocate during request, reset after)
//! - Frame-based allocations in games/simulations
//! - Compiler passes where allocations live for a single phase
//! - Any scenario where allocations have similar lifetimes
//!
//! Limitations:
//! - Cannot free individual allocations
//! - Memory fragmentation if buffer is reused without reset
//! - Fixed-size backing buffer (no growth)

const std = @import("std");

/// A thread-safe bump allocator that allocates memory from a pre-allocated buffer.
///
/// The allocator maintains a position pointer that "bumps" forward with each allocation.
/// Individual deallocations are no-ops; memory is reclaimed by resetting the entire allocator.
///
/// Thread Safety:
/// This implementation uses atomic operations for the position pointer, making it safe
/// to use from multiple threads concurrently. The compare-and-swap loop ensures that
/// allocations don't overlap even under contention.
pub const BumpAllocator = struct {
    /// The backing buffer from which all allocations are served.
    /// Must be aligned to the maximum page size for optimal memory access.
    buffer: []align(std.heap.page_size_max) u8,

    /// The current position in the buffer (next allocation starts here).
    /// Uses atomic operations to ensure thread-safety.
    pos: std.atomic.Value(usize),

    /// Initializes a new BumpAllocator with the given backing buffer.
    ///
    /// Parameters:
    ///   - buffer: A pre-allocated, properly aligned buffer to allocate from
    ///
    /// Returns:
    ///   A new BumpAllocator instance with position set to 0
    ///
    /// Note: The buffer must remain valid for the lifetime of the allocator.
    pub fn init(buffer: []align(std.heap.page_size_max) u8) BumpAllocator {
        return .{
            .buffer = buffer,
            .pos = std.atomic.Value(usize).init(0),
        };
    }

    /// Virtual table for the standard Zig allocator interface.
    /// Defines the implementation functions for allocation operations.
    pub const vtable = std.mem.Allocator.VTable{
        .alloc = alloc,
        .resize = resize,
        .free = free,
        .remap = remap,
    };

    /// Returns a standard Zig allocator interface for this bump allocator.
    ///
    /// This allows the BumpAllocator to be used anywhere a std.mem.Allocator is expected.
    pub fn allocator(self: *BumpAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    /// Attempts to resize/remap an existing allocation in-place.
    ///
    /// This is only possible if the allocation is the most recent one (at the end of the buffer).
    /// If successful, the allocation can grow or shrink without moving.
    ///
    /// Parameters:
    ///   - ctx: Opaque pointer to the BumpAllocator instance
    ///   - buf: The existing allocation to resize
    ///   - ptr_align: Alignment requirement (ignored, existing allocation already satisfies it)
    ///   - new_len: The desired new length
    ///   - ret_addr: Return address for debugging (unused)
    ///
    /// Returns:
    ///   - The original pointer if resize succeeded
    ///   - null if resize failed (allocation wasn't the last one, or not enough space)
    ///
    /// Thread Safety:
    ///   Uses compare-and-swap to atomically update the position pointer.
    fn remap(ctx: *anyopaque, buf: []u8, ptr_align: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        _ = ret_addr;
        _ = ptr_align; // existing buf already satisfies its alignment

        const self: *BumpAllocator = @ptrCast(@alignCast(ctx));

        const base = @intFromPtr(self.buffer.ptr);
        const start = @intFromPtr(buf.ptr);

        // Validate that the buffer belongs to this allocator
        // Must be inside our backing buffer
        if (start < base or start > base + self.buffer.len) return null;

        const start_off: usize = start - base;
        const old_end_off: usize = start_off + buf.len;

        while (true) {
            const end = self.pos.load(.monotonic);

            // Only remap if `buf` is the last allocation
            // If other allocations came after this one, we can't resize in-place
            if (old_end_off != end) return null;

            const new_end_off = start_off + new_len;

            // If growing, must fit in the backing buffer
            if (new_end_off > self.buffer.len) return null;

            // Attempt to update the bump pointer (works for shrink or grow)
            // Compare-and-swap ensures atomicity even with concurrent operations
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
            // This handles the race condition where another thread allocated between
            // our load and cmpxchg operations
        }
    }

    /// Allocates memory from the bump allocator.
    ///
    /// This is the core allocation function. It:
    /// 1. Reads the current position atomically
    /// 2. Aligns the position to meet the alignment requirement
    /// 3. Calculates the new position after allocation
    /// 4. Atomically updates the position using compare-and-swap
    /// 5. Retries if another thread modified the position concurrently
    ///
    /// Parameters:
    ///   - ctx: Opaque pointer to the BumpAllocator instance
    ///   - len: Number of bytes to allocate
    ///   - ptr_align: Required alignment for the allocation
    ///   - ret_addr: Return address for debugging/leak tracking (unused)
    ///
    /// Returns:
    ///   - Pointer to the allocated memory on success
    ///   - null if there's not enough space in the buffer
    ///
    /// Thread Safety:
    ///   Uses atomic compare-and-swap in a retry loop to handle concurrent allocations.
    ///   Multiple threads can safely allocate without external synchronization.
    fn alloc(
        ctx: *anyopaque,
        len: usize,
        ptr_align: std.mem.Alignment,
        ret_addr: usize,
    ) ?[*]u8 {
        // ret_addr is mainly for debugging/leak tracking
        // Custom allocators typically ignore it
        _ = ret_addr;
        const self: *BumpAllocator = @ptrCast(@alignCast(ctx));

        // Load current position atomically
        var current = self.pos.load(.monotonic);

        while (true) {
            // Align the current position to meet the alignment requirement
            // This ensures the returned pointer satisfies alignment constraints
            const aligned_start = std.mem.alignForward(usize, current, ptr_align.toByteUnits());
            const next = aligned_start + len;

            // Check if allocation would exceed buffer bounds
            if (next > self.buffer.len) return null;

            // Try to atomically update the position pointer
            // cmpxchgWeak returns null on success, or the actual current value on failure
            const exchanged = self.pos.cmpxchgWeak(
                current,
                next,
                .monotonic,
                .monotonic,
            ) orelse {
                // Success! Return pointer to the allocated region
                return self.buffer.ptr + aligned_start;
            };

            // CAS failed because another thread modified pos
            // Update current with the actual value and retry
            current = exchanged;
        }
    }

    /// Attempts to resize an allocation in-place by shrinking it.
    ///
    /// This only succeeds if:
    /// 1. The allocation is the most recent one (at the end of used space)
    /// 2. The new size is smaller than or equal to the current size (shrinking only)
    ///
    /// Parameters:
    ///   - ctx: Opaque pointer to the BumpAllocator instance
    ///   - buf: The existing allocation to resize
    ///   - old_align: Original alignment (unused)
    ///   - new_len: Desired new length (must be <= current length)
    ///   - ret_addr: Return address for debugging (unused)
    ///
    /// Returns:
    ///   - true if resize succeeded (allocation can be used at new size)
    ///   - false if resize failed (caller must allocate new memory and copy)
    ///
    /// Note: This implementation checks conditions but doesn't actually update the position.
    /// The allocator is optimized for bulk reset rather than reclaiming individual allocations.
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

        // Only allow resize if this is the last allocation and we're shrinking
        return (buf.ptr + buf.len == self.buffer.ptr + end) and new_len <= buf.len;
    }

    /// Frees an allocation (no-op for bump allocators).
    ///
    /// Bump allocators don't support individual deallocation. Memory is reclaimed
    /// only when reset() is called on the entire allocator.
    ///
    /// This is a key tradeoff: extremely fast allocation in exchange for no individual
    /// deallocation. The pattern is "allocate many, free all at once."
    ///
    /// Parameters:
    ///   - ctx: Opaque pointer to the BumpAllocator instance (unused)
    ///   - buf: The allocation to free (unused)
    ///   - old_align: Alignment of the allocation (unused)
    ///   - ret_addr: Return address for debugging (unused)
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
        // No-op: bump allocators don't free individual allocations
    }

    /// Resets the allocator to its initial state, reclaiming all memory.
    ///
    /// This is the only way to reclaim memory from a bump allocator. After reset,
    /// all previous allocations are considered invalid and must not be accessed.
    ///
    /// Use this when:
    /// - All allocations have the same lifetime (e.g., per-request in a server)
    /// - You're done with a phase of computation
    /// - You want to reuse the backing buffer for a new batch of allocations
    ///
    /// Warning: This does not call destructors or cleanup. Ensure no allocated
    /// objects require cleanup, or handle cleanup before calling reset.
    fn reset(self: *BumpAllocator) void {
        self.pos.store(0, .monotonic);
    }
};

/// Example usage demonstrating bump allocator lifecycle.
///
/// This shows:
/// 1. Creating a backing buffer with proper alignment
/// 2. Initializing the bump allocator
/// 3. Making allocations through the standard allocator interface
/// 4. Resetting the allocator to reclaim all memory
pub fn main() !void {
    // Create a 10 MB backing buffer, aligned to maximum page size
    // This alignment ensures optimal memory access patterns
    var backing: [10 * 1024 * 1024]u8 align(std.heap.page_size_max) = undefined;

    // Initialize the bump allocator with our backing buffer
    var bump = BumpAllocator.init(backing[0..]);

    // Get a standard allocator interface
    const alloc = bump.allocator();

    // Allocate space for 1 million u64 values (8 MB)
    // This comes from the bump allocator's buffer
    const a = try alloc.alloc(u64, 1_000_000);
    _ = a;

    // Could make more allocations here...
    // const b = try alloc.alloc(u32, 500_000);
    // const c = try alloc.alloc(u8, 1024);

    // Reset the allocator, reclaiming all allocated memory
    // After this, 'a' (and any other allocations) are invalid
    bump.reset();

    // The backing buffer can now be reused for new allocations
}
