const std = @import("std");
const buffer_pool = @import("buffer_pool.zig");
const Buffer = buffer_pool.Buffer;
const WorkerBufferPool = buffer_pool.WorkerBufferPool;

/// Maximum buffer capacity per direction: 64 KiB (4 slots of 16 KiB).
pub const MAX_QUEUE_BYTES: usize = 64 * 1024;
pub const MAX_QUEUE_SLOTS: usize = MAX_QUEUE_BYTES / buffer_pool.BUFFER_SIZE;

/// Pre-read budget thresholds for backpressure.
/// When pending bytes exceed 48 KiB, reading from the source is paused before issuing read().
/// When pending bytes fall to 32 KiB or lower, reading is resumed.
pub const THROTTLE_THRESHOLD_BYTES: usize = 48 * 1024;
pub const RESUME_THRESHOLD_BYTES: usize = 32 * 1024;

pub const QueueError = error{
    QueueFull,
    InvalidLength,
    ConsumeOutOfBounds,
};

/// Descriptor of a single pending buffer in the FIFO queue.
pub const QueueSlot = struct {
    buf: Buffer,
    read_offset: usize,
    write_len: usize,

    pub fn availableBytes(self: *const QueueSlot) usize {
        return self.write_len - self.read_offset;
    }

    pub fn getSlice(self: *const QueueSlot) []const u8 {
        return self.buf.memory[self.read_offset..self.write_len];
    }
};

/// Bounded FIFO queue for a single half-duplex direction of a TCP session.
/// Guarantees that new data never overtakes previously buffered data,
/// and preserves remainder offsets upon partial/short writes.
pub const BoundedFifoQueue = struct {
    slots: [MAX_QUEUE_SLOTS]QueueSlot = undefined,
    head: usize = 0,
    count: usize = 0,
    total_pending_bytes: usize = 0,

    pub fn init() BoundedFifoQueue {
        return .{};
    }

    /// Enqueues a newly read buffer to the tail of the queue.
    /// Rejects additions if the slot limit or 64 KiB budget would be exceeded.
    pub fn push(self: *BoundedFifoQueue, buf: Buffer, valid_len: usize) QueueError!void {
        if (valid_len == 0 or valid_len > buffer_pool.BUFFER_SIZE) {
            return QueueError.InvalidLength;
        }

        if (self.count >= MAX_QUEUE_SLOTS) {
            return QueueError.QueueFull;
        }

        if (self.total_pending_bytes + valid_len > MAX_QUEUE_BYTES) {
            return QueueError.QueueFull;
        }

        const tail_index = (self.head + self.count) % MAX_QUEUE_SLOTS;
        self.slots[tail_index] = .{
            .buf = buf,
            .read_offset = 0,
            .write_len = valid_len,
        };

        self.count += 1;
        self.total_pending_bytes += valid_len;
    }

    /// Peeks at the unwritten slice at the head of the queue.
    /// Returns null if the queue is empty.
    pub fn peek(self: *const BoundedFifoQueue) ?[]const u8 {
        if (self.count == 0) return null;
        return self.slots[self.head].getSlice();
    }

    /// Consumes up to `bytes` from the head buffer.
    /// If the head buffer is completely drained, it is dequeued and returned
    /// so the caller can return it to the WorkerBufferPool.
    /// If a partial write occurred, the buffer remains at the head with an advanced read_offset,
    /// and null is returned.
    pub fn consume(self: *BoundedFifoQueue, bytes: usize) QueueError!?Buffer {
        if (bytes == 0) return null;
        if (self.count == 0) return QueueError.ConsumeOutOfBounds;

        const slot = &self.slots[self.head];
        const avail = slot.availableBytes();
        if (bytes > avail) return QueueError.ConsumeOutOfBounds;

        slot.read_offset += bytes;
        self.total_pending_bytes -= bytes;

        if (slot.read_offset == slot.write_len) {
            const finished_buf = slot.buf;
            self.head = (self.head + 1) % MAX_QUEUE_SLOTS;
            self.count -= 1;
            return finished_buf;
        }

        return null;
    }

    /// Total number of pending unwritten bytes across all queued buffers.
    pub fn pendingBytes(self: *const BoundedFifoQueue) usize {
        return self.total_pending_bytes;
    }

    /// Number of active buffer slots in the queue.
    pub fn slotCount(self: *const BoundedFifoQueue) usize {
        return self.count;
    }

    /// Returns true if there are no pending bytes to write.
    pub fn isEmpty(self: *const BoundedFifoQueue) bool {
        return self.count == 0;
    }

    /// Returns true if the queue has reached either slot limit or 64 KiB capacity.
    pub fn isFull(self: *const BoundedFifoQueue) bool {
        return self.count >= MAX_QUEUE_SLOTS or self.total_pending_bytes >= MAX_QUEUE_BYTES;
    }

    /// Returns true if the queue has capacity for an incoming read buffer:
    /// requires a free slot (count < 4) AND pending bytes within throttle limit (<= 48 KiB).
    pub fn canAcceptRead(self: *const BoundedFifoQueue) bool {
        return self.count < MAX_QUEUE_SLOTS and self.total_pending_bytes <= THROTTLE_THRESHOLD_BYTES;
    }

    /// Returns true when reading from the source must be paused:
    /// triggered if all slots are occupied (count >= 4) OR pending bytes exceed 48 KiB.
    pub fn shouldThrottleReader(self: *const BoundedFifoQueue) bool {
        return self.count >= MAX_QUEUE_SLOTS or self.total_pending_bytes > THROTTLE_THRESHOLD_BYTES;
    }

    /// Returns true when reading from the source can be safely resumed:
    /// requires at least one free slot (count < 4) AND pending bytes drained to 32 KiB or lower.
    /// A partial write that does not retire a buffer leaves count unchanged and will not resume.
    pub fn canResumeReader(self: *const BoundedFifoQueue) bool {
        return self.count < MAX_QUEUE_SLOTS and self.total_pending_bytes <= RESUME_THRESHOLD_BYTES;
    }

    /// Alias for canResumeReader for backward compatibility.
    pub fn shouldResumeReader(self: *const BoundedFifoQueue) bool {
        return self.canResumeReader();
    }

    /// Abortively releases all buffers held in the queue back to the pool.
    /// Propagates any BufferPoolError while ensuring release is attempted for all queued slots.
    pub fn dropAll(self: *BoundedFifoQueue, pool: *WorkerBufferPool) buffer_pool.BufferPoolError!void {
        var first_err: ?buffer_pool.BufferPoolError = null;
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const idx = (self.head + i) % MAX_QUEUE_SLOTS;
            pool.release(self.slots[idx].buf) catch |err| {
                if (first_err == null) first_err = err;
            };
        }
        self.head = 0;
        self.count = 0;
        self.total_pending_bytes = 0;
        if (first_err) |err| return err;
    }
};

test "BoundedFifoQueue push, peek, consume full buffer" {
    const allocator = std.testing.allocator;
    var pool = try WorkerBufferPool.init(allocator, 4);
    defer pool.deinit(allocator);

    var queue = BoundedFifoQueue.init();

    const b0 = pool.acquire().?;
    @memcpy(b0.memory[0..4], "ABCD");
    try queue.push(b0, 4);

    try std.testing.expectEqual(@as(usize, 4), queue.pendingBytes());
    try std.testing.expectEqualStrings("ABCD", queue.peek().?);

    const released = (try queue.consume(4)).?;
    try std.testing.expectEqual(b0.index, released.index);
    try std.testing.expect(queue.isEmpty());
    try std.testing.expect(queue.peek() == null);

    try pool.release(released);
}

test "BoundedFifoQueue partial write maintains remainder and strict FIFO order" {
    const allocator = std.testing.allocator;
    var pool = try WorkerBufferPool.init(allocator, 4);
    defer pool.deinit(allocator);

    var queue = BoundedFifoQueue.init();

    const b0 = pool.acquire().?;
    @memcpy(b0.memory[0..6], "HELLO_");
    try queue.push(b0, 6);

    const b1 = pool.acquire().?;
    @memcpy(b1.memory[0..5], "WORLD");
    try queue.push(b1, 5);

    try std.testing.expectEqual(@as(usize, 11), queue.pendingBytes());

    // Partial consume of 2 bytes from "HELLO_" -> should leave "LLO_" at head
    const r0 = try queue.consume(2);
    try std.testing.expect(r0 == null);
    try std.testing.expectEqual(@as(usize, 9), queue.pendingBytes());
    try std.testing.expectEqualStrings("LLO_", queue.peek().?);

    // Consume next 4 bytes from "HELLO_" -> drains b0
    const r1 = (try queue.consume(4)).?;
    try std.testing.expectEqual(b0.index, r1.index);
    try pool.release(r1);

    // Now head must be "WORLD" from b1 without data reordering
    try std.testing.expectEqual(@as(usize, 5), queue.pendingBytes());
    try std.testing.expectEqualStrings("WORLD", queue.peek().?);

    // Consume all 5 bytes of b1
    const r2 = (try queue.consume(5)).?;
    try std.testing.expectEqual(b1.index, r2.index);
    try pool.release(r2);

    try std.testing.expect(queue.isEmpty());
}

test "BoundedFifoQueue enforces 64 KiB capacity limit" {
    const allocator = std.testing.allocator;
    var pool = try WorkerBufferPool.init(allocator, 5);
    defer pool.deinit(allocator);

    var queue = BoundedFifoQueue.init();

    // 4 buffers of 16 KiB = exactly 64 KiB
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const b = pool.acquire().?;
        try queue.push(b, buffer_pool.BUFFER_SIZE);
    }

    try std.testing.expectEqual(MAX_QUEUE_BYTES, queue.pendingBytes());
    try std.testing.expect(queue.isFull());
    try std.testing.expect(queue.shouldThrottleReader());

    // 5th buffer must be rejected with QueueFull
    const b_extra = pool.acquire().?;
    const err = queue.push(b_extra, 1);
    try std.testing.expectError(QueueError.QueueFull, err);
    try pool.release(b_extra);

    // Drain everything to pool
    try queue.dropAll(&pool);
    try std.testing.expect(queue.isEmpty());
    try std.testing.expectEqual(@as(usize, 5), pool.available());
}

test "BoundedFifoQueue backpressure hysteresis thresholds" {
    const allocator = std.testing.allocator;
    var pool = try WorkerBufferPool.init(allocator, 4);
    defer pool.deinit(allocator);

    var queue = BoundedFifoQueue.init();

    // 3 buffers * 16 KiB = 48 KiB -> not > 48 KiB yet
    const b0 = pool.acquire().?;
    const b1 = pool.acquire().?;
    const b2 = pool.acquire().?;
    try queue.push(b0, 16 * 1024);
    try queue.push(b1, 16 * 1024);
    try queue.push(b2, 16 * 1024);

    try std.testing.expectEqual(@as(usize, 48 * 1024), queue.pendingBytes());
    try std.testing.expect(!queue.shouldThrottleReader());

    // Adding 1 byte pushes queue to 48 KiB + 1 -> must trigger throttle
    const b3 = pool.acquire().?;
    try queue.push(b3, 1024);
    try std.testing.expect(queue.shouldThrottleReader());

    // Consume until <= 32 KiB -> resume trigger
    // Consume b0 (16 KiB) -> remaining is 33 KiB
    const r0 = (try queue.consume(16 * 1024)).?;
    try pool.release(r0);
    try std.testing.expect(!queue.shouldResumeReader()); // 33 KiB > 32 KiB

    // Consume 1 KiB -> remaining is 32 KiB -> resume reader
    _ = try queue.consume(1024);
    try std.testing.expect(queue.shouldResumeReader());

    try queue.dropAll(&pool);
}

test "BoundedFifoQueue slot exhaustion throttles reader despite small byte count" {
    const allocator = std.testing.allocator;
    var pool = try WorkerBufferPool.init(allocator, 5);
    defer pool.deinit(allocator);

    var queue = BoundedFifoQueue.init();

    // 4 short reads of 100 bytes each: total bytes = 400 (< 48 KiB), but all 4 slots occupied
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const b = pool.acquire().?;
        try queue.push(b, 100);
    }

    try std.testing.expectEqual(@as(usize, 4), queue.slotCount());
    try std.testing.expectEqual(@as(usize, 400), queue.pendingBytes());
    try std.testing.expect(queue.isFull());
    // Must throttle despite pending bytes being far below 48 KiB
    try std.testing.expect(queue.shouldThrottleReader());
    try std.testing.expect(!queue.canAcceptRead());

    // Partial write of 50 bytes from head buffer: does NOT free slot
    const consumed_null = try queue.consume(50);
    try std.testing.expect(consumed_null == null);
    try std.testing.expectEqual(@as(usize, 4), queue.slotCount());
    // Reader must NOT be resumed because all slots are still occupied
    try std.testing.expect(!queue.canResumeReader());

    // Fully consume the remaining 50 bytes of head buffer: frees slot
    const freed_buf = (try queue.consume(50)).?;
    try pool.release(freed_buf);
    try std.testing.expectEqual(@as(usize, 3), queue.slotCount());
    // Now with a free slot and bytes <= 32 KiB, reader CAN resume
    try std.testing.expect(queue.canResumeReader());
    try std.testing.expect(queue.canAcceptRead());

    try queue.dropAll(&pool);
    try std.testing.expectEqual(@as(usize, 5), pool.available());
}
