const std = @import("std");

/// Fixed size of every buffer slot in the pool (16 KiB).
pub const BUFFER_SIZE: usize = 16 * 1024;

/// Handle to an acquired buffer with explicit index and generation tracking.
pub const Buffer = struct {
    index: usize,
    generation: u32,
    memory: *[BUFFER_SIZE]u8,
};

pub const BufferPoolError = error{
    OutOfMemory,
    PoolExhausted,
    InvalidBufferIndex,
    DoubleRelease,
    ForeignBuffer,
    StaleBufferGeneration,
};

/// Thread-local buffer pool with fixed capacity.
/// Allocates all memory contiguously upon initialization and performs
/// zero dynamic heap allocations during steady-state processing.
pub const WorkerBufferPool = struct {
    raw_memory: []u8,
    free_stack: []usize,
    in_use: []bool,
    generations: []u32,
    capacity: usize,
    free_count: usize,

    /// Initializes a pool with fixed capacity.
    /// Allocates contiguous buffer storage and index metadata upfront.
    pub fn init(allocator: std.mem.Allocator, capacity: usize) BufferPoolError!WorkerBufferPool {
        if (capacity == 0) return BufferPoolError.PoolExhausted;

        const total_bytes = std.math.mul(usize, capacity, BUFFER_SIZE) catch {
            return BufferPoolError.OutOfMemory;
        };

        const raw_memory = allocator.alloc(u8, total_bytes) catch {
            return BufferPoolError.OutOfMemory;
        };
        errdefer allocator.free(raw_memory);

        const free_stack = allocator.alloc(usize, capacity) catch {
            return BufferPoolError.OutOfMemory;
        };
        errdefer allocator.free(free_stack);

        const in_use = allocator.alloc(bool, capacity) catch {
            return BufferPoolError.OutOfMemory;
        };
        errdefer allocator.free(in_use);

        const generations = allocator.alloc(u32, capacity) catch {
            return BufferPoolError.OutOfMemory;
        };
        errdefer allocator.free(generations);

        for (0..capacity) |i| {
            free_stack[i] = i;
            in_use[i] = false;
            generations[i] = 1;
        }

        return .{
            .raw_memory = raw_memory,
            .free_stack = free_stack,
            .in_use = in_use,
            .generations = generations,
            .capacity = capacity,
            .free_count = capacity,
        };
    }

    /// Releases all preallocated memory.
    /// In debug/safe builds, asserts that all buffers have been returned.
    pub fn deinit(self: *WorkerBufferPool, allocator: std.mem.Allocator) void {
        std.debug.assert(self.free_count == self.capacity);
        allocator.free(self.generations);
        allocator.free(self.in_use);
        allocator.free(self.free_stack);
        allocator.free(self.raw_memory);
        self.* = undefined;
    }

    /// Acquires a 16 KiB buffer slot from the pool.
    /// Returns null if the pool is exhausted; never allocates from the general heap.
    pub fn acquire(self: *WorkerBufferPool) ?Buffer {
        if (self.free_count == 0) return null;

        self.free_count -= 1;
        const index = self.free_stack[self.free_count];
        std.debug.assert(!self.in_use[index]);
        self.in_use[index] = true;

        const start = index * BUFFER_SIZE;
        const slice = self.raw_memory[start .. start + BUFFER_SIZE];
        const ptr: *[BUFFER_SIZE]u8 = @ptrCast(slice.ptr);

        return Buffer{
            .index = index,
            .generation = self.generations[index],
            .memory = ptr,
        };
    }

    /// Returns a previously acquired buffer to the pool.
    /// Validates ownership, index bounds, generation match, and detects double-free.
    pub fn release(self: *WorkerBufferPool, buffer: Buffer) BufferPoolError!void {
        if (buffer.index >= self.capacity) {
            return BufferPoolError.InvalidBufferIndex;
        }

        const expected_start = buffer.index * BUFFER_SIZE;
        if (buffer.memory != @as(*[BUFFER_SIZE]u8, @ptrCast(self.raw_memory[expected_start..].ptr))) {
            return BufferPoolError.ForeignBuffer;
        }

        if (!self.in_use[buffer.index]) {
            return BufferPoolError.DoubleRelease;
        }

        if (buffer.generation != self.generations[buffer.index]) {
            return BufferPoolError.StaleBufferGeneration;
        }

        self.generations[buffer.index] +%= 1;
        if (self.generations[buffer.index] == 0) {
            self.generations[buffer.index] = 1;
        }

        self.in_use[buffer.index] = false;
        self.free_stack[self.free_count] = buffer.index;
        self.free_count += 1;
    }

    /// Returns the number of currently available free buffer slots.
    pub fn available(self: *const WorkerBufferPool) usize {
        return self.free_count;
    }

    /// Returns true if all buffers are currently in use.
    pub fn isExhausted(self: *const WorkerBufferPool) bool {
        return self.free_count == 0;
    }
};

test "WorkerBufferPool basic acquire and release" {
    const allocator = std.testing.allocator;
    var pool = try WorkerBufferPool.init(allocator, 4);
    defer pool.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 4), pool.available());
    try std.testing.expect(!pool.isExhausted());

    const b0 = pool.acquire().?;
    const b1 = pool.acquire().?;
    try std.testing.expectEqual(@as(usize, 2), pool.available());

    b0.memory[0] = 0xAA;
    b1.memory[BUFFER_SIZE - 1] = 0xBB;
    try std.testing.expectEqual(@as(u8, 0xAA), b0.memory[0]);
    try std.testing.expectEqual(@as(u8, 0xBB), b1.memory[BUFFER_SIZE - 1]);

    try pool.release(b0);
    try std.testing.expectEqual(@as(usize, 3), pool.available());

    try pool.release(b1);
    try std.testing.expectEqual(@as(usize, 4), pool.available());
}

test "WorkerBufferPool exhaustion returns null without heap fallback" {
    const allocator = std.testing.allocator;
    var pool = try WorkerBufferPool.init(allocator, 2);
    defer pool.deinit(allocator);

    const b0 = pool.acquire().?;
    const b1 = pool.acquire().?;
    try std.testing.expect(pool.isExhausted());

    const b2 = pool.acquire();
    try std.testing.expect(b2 == null);

    try pool.release(b0);
    try std.testing.expect(!pool.isExhausted());

    const b3 = pool.acquire().?;
    try std.testing.expectEqual(b0.index, b3.index);

    try pool.release(b1);
    try pool.release(b3);
}

test "WorkerBufferPool detects double release" {
    const allocator = std.testing.allocator;
    var pool = try WorkerBufferPool.init(allocator, 2);
    defer pool.deinit(allocator);

    const b0 = pool.acquire().?;
    try pool.release(b0);

    const err = pool.release(b0);
    try std.testing.expectError(BufferPoolError.DoubleRelease, err);
}

test "WorkerBufferPool init handles allocation failures without leaks" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var pool = try WorkerBufferPool.init(allocator, 8);
            defer pool.deinit(allocator);

            const b = pool.acquire() orelse return error.TestUnexpectedResult;
            try pool.release(b);
        }
    }.run, .{});
}

test "WorkerBufferPool detects stale handle via generation token" {
    const allocator = std.testing.allocator;
    var pool = try WorkerBufferPool.init(allocator, 1);
    defer pool.deinit(allocator);

    const b0 = pool.acquire().?;
    try std.testing.expectEqual(@as(u32, 1), b0.generation);
    try pool.release(b0);

    // Re-acquire the same slot -> new generation token
    const b1 = pool.acquire().?;
    try std.testing.expectEqual(b0.index, b1.index);
    try std.testing.expectEqual(@as(u32, 2), b1.generation);

    // Attempting to release using the stale handle b0 must fail with StaleBufferGeneration
    const err = pool.release(b0);
    try std.testing.expectError(BufferPoolError.StaleBufferGeneration, err);

    // Releasing with the valid handle b1 must succeed
    try pool.release(b1);
    try std.testing.expectEqual(@as(usize, 1), pool.available());
}
