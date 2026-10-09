const std = @import("std");
const buffer_pool = @import("buffer_pool.zig");
const fifo_queue = @import("fifo_queue.zig");

const Buffer = buffer_pool.Buffer;
const WorkerBufferPool = buffer_pool.WorkerBufferPool;
const BoundedFifoQueue = fifo_queue.BoundedFifoQueue;

/// Traffic direction in a full-duplex TCP proxy session.
pub const Direction = enum(u1) {
    client_to_target = 0,
    target_to_client = 1,

    pub fn opposite(self: Direction) Direction {
        return switch (self) {
            .client_to_target => .target_to_client,
            .target_to_client => .client_to_target,
        };
    }
};

/// Half-duplex state machine conforming to RFC 9293 §3.6.1.
pub const StreamState = enum {
    streaming,
    source_eof,
    draining,
    half_closed,
};

/// Overall lifecycle status of the bidirectional TCP session.
pub const SessionStatus = enum {
    active,
    terminated,
    aborted,
};

pub const TcpLifecycleError = error{
    SessionNotActive,
    StreamNotStreaming,
    QueueFull,
    InvalidLength,
};

/// Actions required from the I/O event reactor upon state transitions.
pub const LifecycleAction = struct {
    unregister_source_read: bool = false,
    resume_source_read: bool = false,
    register_dest_write: bool = false,
    unregister_dest_write: bool = false,
    shutdown_dest_write: bool = false,
    session_terminated: bool = false,
};

/// Result of processing a write event on the destination socket.
pub const WriteResult = struct {
    consumed_buf: ?Buffer = null,
    action: LifecycleAction = .{},
};

/// Manages the dual-direction TCP session lifecycle, independent half-close transitions,
/// bounded FIFO queues, drain deadlines, and immediate abortive cancellation.
pub const TcpLifecycle = struct {
    queues: [2]BoundedFifoQueue,
    stream_state: [2]StreamState,
    session_status: SessionStatus,
    drain_deadline_ms: [2]?i64,
    default_drain_timeout_ms: i64,

    pub fn init(default_drain_timeout_ms: i64) TcpLifecycle {
        return .{
            .queues = .{ BoundedFifoQueue.init(), BoundedFifoQueue.init() },
            .stream_state = .{ .streaming, .streaming },
            .session_status = .active,
            .drain_deadline_ms = .{ null, null },
            .default_drain_timeout_ms = default_drain_timeout_ms,
        };
    }

    /// Checks whether the source socket for `dir` can be polled for reading.
    /// Returns false if session is inactive, stream is not streaming, or the queue cannot accept read.
    pub fn canReadSource(self: *const TcpLifecycle, dir: Direction) bool {
        if (self.session_status != .active) return false;
        const d_idx = @intFromEnum(dir);
        if (self.stream_state[d_idx] != .streaming) return false;
        return self.queues[d_idx].canAcceptRead();
    }

    /// Checks whether the destination socket for `dir` has pending data to write.
    pub fn canWriteDest(self: *const TcpLifecycle, dir: Direction) bool {
        if (self.session_status != .active) return false;
        const d_idx = @intFromEnum(dir);
        if (self.stream_state[d_idx] == .half_closed) return false;
        return !self.queues[d_idx].isEmpty();
    }

    /// Enqueues newly read payload into the queue of direction `dir`.
    /// On error, ownership of `buf` is NOT taken by TcpLifecycle;
    /// caller retains ownership and is responsible for returning `buf` to WorkerBufferPool.
    pub fn onDataRead(self: *TcpLifecycle, dir: Direction, buf: Buffer, len: usize) TcpLifecycleError!LifecycleAction {
        if (self.session_status != .active) {
            return TcpLifecycleError.SessionNotActive;
        }

        const d_idx = @intFromEnum(dir);
        if (self.stream_state[d_idx] != .streaming) {
            return TcpLifecycleError.StreamNotStreaming;
        }

        self.queues[d_idx].push(buf, len) catch |err| switch (err) {
            fifo_queue.QueueError.QueueFull => return TcpLifecycleError.QueueFull,
            fifo_queue.QueueError.InvalidLength => return TcpLifecycleError.InvalidLength,
            fifo_queue.QueueError.ConsumeOutOfBounds => unreachable,
        };

        var action = LifecycleAction{};
        action.register_dest_write = true;

        if (self.queues[d_idx].shouldThrottleReader()) {
            action.unregister_source_read = true;
        }

        return action;
    }

    /// Processes an EOF (read == 0) from the source socket of direction `dir`.
    /// Reading on the source is permanently removed and will NEVER resume.
    /// If queue is empty, immediately transitions to half_closed and issues SHUT_WR.
    /// If queue has pending data, transitions to draining and sets a deadline timer.
    pub fn onSourceEof(self: *TcpLifecycle, dir: Direction, now_ms: i64) LifecycleAction {
        const d_idx = @intFromEnum(dir);
        var action = LifecycleAction{
            .unregister_source_read = true,
        };

        if (self.stream_state[d_idx] != .streaming) {
            return action;
        }

        if (self.queues[d_idx].isEmpty()) {
            self.stream_state[d_idx] = .half_closed;
            action.shutdown_dest_write = true;
            action.unregister_dest_write = true;

            const opp_idx = @intFromEnum(dir.opposite());
            if (self.stream_state[opp_idx] == .half_closed) {
                self.session_status = .terminated;
                action.session_terminated = true;
            }
        } else {
            self.stream_state[d_idx] = .draining;
            self.drain_deadline_ms[d_idx] = now_ms + self.default_drain_timeout_ms;
            action.register_dest_write = true;
        }

        return action;
    }

    /// Processes bytes written to the destination socket for direction `dir`.
    /// Returns any fully drained buffer so the caller can return it to WorkerBufferPool.
    pub fn onDestWrite(self: *TcpLifecycle, dir: Direction, bytes_written: usize) !WriteResult {
        const d_idx = @intFromEnum(dir);
        const consumed_buf = try self.queues[d_idx].consume(bytes_written);

        var action = LifecycleAction{};

        if (self.queues[d_idx].canResumeReader() and self.stream_state[d_idx] == .streaming) {
            action.resume_source_read = true;
        }

        if (self.queues[d_idx].isEmpty()) {
            action.unregister_dest_write = true;

            if (self.stream_state[d_idx] == .draining) {
                self.stream_state[d_idx] = .half_closed;
                self.drain_deadline_ms[d_idx] = null;
                action.shutdown_dest_write = true;

                const opp_idx = @intFromEnum(dir.opposite());
                if (self.stream_state[opp_idx] == .half_closed) {
                    self.session_status = .terminated;
                    action.session_terminated = true;
                }
            }
        } else {
            action.register_dest_write = true;
        }

        return WriteResult{
            .consumed_buf = consumed_buf,
            .action = action,
        };
    }

    /// Checks if the drain deadline has expired for direction `dir`.
    /// If expired, immediately aborts the session and releases all buffers to `pool`.
    pub fn checkDrainDeadline(
        self: *TcpLifecycle,
        dir: Direction,
        now_ms: i64,
        pool: *WorkerBufferPool,
    ) buffer_pool.BufferPoolError!bool {
        const d_idx = @intFromEnum(dir);
        if (self.stream_state[d_idx] == .draining) {
            if (self.drain_deadline_ms[d_idx]) |deadline| {
                if (now_ms >= deadline) {
                    try self.abort(pool);
                    return true;
                }
            }
        }
        return false;
    }

    /// Abortively cancels the session without graceful drain.
    /// Drops all queued buffers immediately back to `pool` and marks session aborted.
    pub fn abort(self: *TcpLifecycle, pool: *WorkerBufferPool) buffer_pool.BufferPoolError!void {
        var first_err: ?buffer_pool.BufferPoolError = null;
        self.queues[0].dropAll(pool) catch |err| {
            if (first_err == null) first_err = err;
        };
        self.queues[1].dropAll(pool) catch |err| {
            if (first_err == null) first_err = err;
        };
        self.stream_state[0] = .half_closed;
        self.stream_state[1] = .half_closed;
        self.drain_deadline_ms = .{ null, null };
        self.session_status = .aborted;
        if (first_err) |err| return err;
    }

    /// Returns true if both half-duplex directions are finished or session was aborted.
    pub fn isTerminated(self: *const TcpLifecycle) bool {
        return self.session_status == .terminated or self.session_status == .aborted;
    }
};

test "TcpLifecycle client-first EOF allows full server response and symmetric close" {
    const allocator = std.testing.allocator;
    var pool = try WorkerBufferPool.init(allocator, 8);
    defer pool.deinit(allocator);

    var lifecycle = TcpLifecycle.init(5000);

    // 1. Client sends request data (c2t)
    const b0 = pool.acquire().?;
    @memcpy(b0.memory[0..5], "PING\n");
    _ = try lifecycle.onDataRead(.client_to_target, b0, 5);

    // 2. Client sends EOF (Client-first EOF)
    const eof_act0 = lifecycle.onSourceEof(.client_to_target, 1000);
    try std.testing.expect(eof_act0.unregister_source_read);
    try std.testing.expect(eof_act0.register_dest_write);
    try std.testing.expectEqual(StreamState.draining, lifecycle.stream_state[@intFromEnum(Direction.client_to_target)]);

    // READ on client is NEVER resumed after EOF
    try std.testing.expect(!lifecycle.canReadSource(.client_to_target));

    // Meanwhile, target-to-client is fully active and can stream server response!
    try std.testing.expect(lifecycle.canReadSource(.target_to_client));
    const b_resp = pool.acquire().?;
    @memcpy(b_resp.memory[0..6], "PONG\r\n");
    _ = try lifecycle.onDataRead(.target_to_client, b_resp, 6);

    // 3. Drain client request to target
    const wr0 = try lifecycle.onDestWrite(.client_to_target, 5);
    try std.testing.expect(wr0.action.shutdown_dest_write);
    try std.testing.expectEqual(StreamState.half_closed, lifecycle.stream_state[@intFromEnum(Direction.client_to_target)]);
    try pool.release(wr0.consumed_buf.?);

    // Session is NOT terminated yet because server hasn't sent its response EOF!
    try std.testing.expect(!lifecycle.isTerminated());

    // 4. Drain server response to client
    const wr_resp = try lifecycle.onDestWrite(.target_to_client, 6);
    try pool.release(wr_resp.consumed_buf.?);

    // 5. Server sends EOF
    const eof_act1 = lifecycle.onSourceEof(.target_to_client, 1050);
    try std.testing.expect(eof_act1.shutdown_dest_write);
    try std.testing.expect(eof_act1.session_terminated);
    try std.testing.expectEqual(StreamState.half_closed, lifecycle.stream_state[@intFromEnum(Direction.target_to_client)]);
    try std.testing.expect(lifecycle.isTerminated());
}

test "TcpLifecycle server-first EOF allows full client drain without tail loss" {
    const allocator = std.testing.allocator;
    var pool = try WorkerBufferPool.init(allocator, 8);
    defer pool.deinit(allocator);

    var lifecycle = TcpLifecycle.init(5000);

    // 1. Server sends large response before closing (t2c)
    const b_resp = pool.acquire().?;
    @memcpy(b_resp.memory[0..12], "HTTP_OK_DATA");
    _ = try lifecycle.onDataRead(.target_to_client, b_resp, 12);

    // 2. Server sends EOF first (Server-first EOF)
    const eof_server = lifecycle.onSourceEof(.target_to_client, 2000);
    try std.testing.expect(eof_server.unregister_source_read);
    try std.testing.expect(eof_server.register_dest_write);
    try std.testing.expectEqual(StreamState.draining, lifecycle.stream_state[@intFromEnum(Direction.target_to_client)]);

    // Slow client reads 4 bytes partially (short write)
    const wr_part = try lifecycle.onDestWrite(.target_to_client, 4);
    try std.testing.expect(wr_part.consumed_buf == null); // buffer not freed yet
    try std.testing.expectEqual(StreamState.draining, lifecycle.stream_state[@intFromEnum(Direction.target_to_client)]);
    try std.testing.expect(!lifecycle.isTerminated());

    // Slow client finishes remaining 8 bytes
    const wr_done = try lifecycle.onDestWrite(.target_to_client, 8);
    try std.testing.expect(wr_done.action.shutdown_dest_write);
    try std.testing.expectEqual(StreamState.half_closed, lifecycle.stream_state[@intFromEnum(Direction.target_to_client)]);
    try pool.release(wr_done.consumed_buf.?);

    // Client sends its EOF
    const eof_client = lifecycle.onSourceEof(.client_to_target, 2100);
    try std.testing.expect(eof_client.shutdown_dest_write);
    try std.testing.expect(eof_client.session_terminated);
    try std.testing.expect(lifecycle.isTerminated());
}

test "TcpLifecycle drain deadline timeout forces abort" {
    const allocator = std.testing.allocator;
    var pool = try WorkerBufferPool.init(allocator, 4);
    defer pool.deinit(allocator);

    var lifecycle = TcpLifecycle.init(5000);

    const b = pool.acquire().?;
    _ = try lifecycle.onDataRead(.client_to_target, b, 100);
    _ = lifecycle.onSourceEof(.client_to_target, 1000);

    // At now_ms = 5999, deadline has not expired yet
    try std.testing.expect(!try lifecycle.checkDrainDeadline(.client_to_target, 5999, &pool));
    try std.testing.expect(!lifecycle.isTerminated());

    // At now_ms = 6000, 5000 ms expired -> aborts and drops buffer to pool
    try std.testing.expect(try lifecycle.checkDrainDeadline(.client_to_target, 6000, &pool));
    try std.testing.expect(lifecycle.isTerminated());
    try std.testing.expectEqual(SessionStatus.aborted, lifecycle.session_status);
    try std.testing.expectEqual(@as(usize, 4), pool.available());
}

test "TcpLifecycle immediate abort drops all queues to pool" {
    const allocator = std.testing.allocator;
    var pool = try WorkerBufferPool.init(allocator, 8);
    defer pool.deinit(allocator);

    var lifecycle = TcpLifecycle.init(5000);

    // Populate both queues
    const b0 = pool.acquire().?;
    const b1 = pool.acquire().?;
    _ = try lifecycle.onDataRead(.client_to_target, b0, 50);
    _ = try lifecycle.onDataRead(.target_to_client, b1, 60);

    try std.testing.expectEqual(@as(usize, 6), pool.available());

    // User Eviction abort
    try lifecycle.abort(&pool);

    try std.testing.expect(lifecycle.isTerminated());
    try std.testing.expectEqual(SessionStatus.aborted, lifecycle.session_status);
    try std.testing.expectEqual(@as(usize, 8), pool.available());
}

test "TcpLifecycle dual queue filling up to 64 KiB each" {
    const allocator = std.testing.allocator;
    var pool = try WorkerBufferPool.init(allocator, 8);
    defer pool.deinit(allocator);

    var lifecycle = TcpLifecycle.init(5000);

    // Fill both directions with 4 * 16 KiB = 64 KiB each
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const b_c2t = pool.acquire().?;
        _ = try lifecycle.onDataRead(.client_to_target, b_c2t, buffer_pool.BUFFER_SIZE);

        const b_t2c = pool.acquire().?;
        _ = try lifecycle.onDataRead(.target_to_client, b_t2c, buffer_pool.BUFFER_SIZE);
    }

    try std.testing.expectEqual(@as(usize, 0), pool.available());
    try std.testing.expect(lifecycle.queues[0].isFull());
    try std.testing.expect(lifecycle.queues[1].isFull());

    // Both directions should throttle reader
    try std.testing.expect(!lifecycle.canReadSource(.client_to_target));
    try std.testing.expect(!lifecycle.canReadSource(.target_to_client));

    // Abort drops all 8 buffers
    try lifecycle.abort(&pool);
    try std.testing.expectEqual(@as(usize, 8), pool.available());
}

test "TcpLifecycle late onDataRead after EOF returns error.StreamNotStreaming and caller retains buffer ownership" {
    const allocator = std.testing.allocator;
    var pool = try WorkerBufferPool.init(allocator, 4);
    defer pool.deinit(allocator);

    var lifecycle = TcpLifecycle.init(5000);

    // 1. Initial read
    const b0 = pool.acquire().?;
    _ = try lifecycle.onDataRead(.client_to_target, b0, 10);

    // 2. Client EOF arrives -> stream transitions to draining
    _ = lifecycle.onSourceEof(.client_to_target, 1000);
    try std.testing.expectEqual(StreamState.draining, lifecycle.stream_state[@intFromEnum(Direction.client_to_target)]);

    // 3. Spurious late read arriving after EOF must be rejected with typed error (no panic)
    const b_late = pool.acquire().?;
    const res = lifecycle.onDataRead(.client_to_target, b_late, 10);
    try std.testing.expectError(TcpLifecycleError.StreamNotStreaming, res);

    // 4. Since onDataRead errored, caller retains ownership of b_late and safely returns it to pool
    try pool.release(b_late);

    // 5. Complete draining of the valid initial buffer
    const wr = try lifecycle.onDestWrite(.client_to_target, 10);
    try pool.release(wr.consumed_buf.?);

    try std.testing.expectEqual(StreamState.half_closed, lifecycle.stream_state[@intFromEnum(Direction.client_to_target)]);
    try std.testing.expectEqual(@as(usize, 4), pool.available());
}

test "TcpLifecycle late onDataRead after abort returns error.SessionNotActive and caller retains buffer ownership" {
    const allocator = std.testing.allocator;
    var pool = try WorkerBufferPool.init(allocator, 4);
    defer pool.deinit(allocator);

    var lifecycle = TcpLifecycle.init(5000);

    const b0 = pool.acquire().?;
    _ = try lifecycle.onDataRead(.client_to_target, b0, 10);

    // Immediate abort (e.g. user eviction or error)
    try lifecycle.abort(&pool);
    try std.testing.expect(lifecycle.isTerminated());

    // Spurious late read arriving after abort must return SessionNotActive without panicking
    const b_late = pool.acquire().?;
    const res = lifecycle.onDataRead(.client_to_target, b_late, 10);
    try std.testing.expectError(TcpLifecycleError.SessionNotActive, res);

    // Caller safely returns unaccepted buffer to pool
    try pool.release(b_late);
    try std.testing.expectEqual(@as(usize, 4), pool.available());
}

test "TcpLifecycle 4 short reads fill slots and throttle reader; partial write does not resume" {
    const allocator = std.testing.allocator;
    var pool = try WorkerBufferPool.init(allocator, 5);
    defer pool.deinit(allocator);

    var lifecycle = TcpLifecycle.init(5000);

    // Push 4 short reads of 50 bytes each (total bytes = 200, but 4 slots occupied)
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const b = pool.acquire().?;
        _ = try lifecycle.onDataRead(.client_to_target, b, 50);
    }

    // All slots are occupied: canReadSource must be false despite byte count being << 48 KiB
    try std.testing.expect(!lifecycle.canReadSource(.client_to_target));

    // Partial write of 20 bytes from head buffer: does NOT free a slot
    const wr_part = try lifecycle.onDestWrite(.client_to_target, 20);
    try std.testing.expect(wr_part.consumed_buf == null);
    // Reader must NOT be resumed because all slots remain occupied
    try std.testing.expect(!wr_part.action.resume_source_read);
    try std.testing.expect(!lifecycle.canReadSource(.client_to_target));

    // Complete write of remaining 30 bytes in head buffer: frees slot
    const wr_drain = try lifecycle.onDestWrite(.client_to_target, 30);
    const b_freed = wr_drain.consumed_buf.?;
    try pool.release(b_freed);
    // Now with a free slot (count == 3) and bytes <= 32 KiB, reader IS resumed
    try std.testing.expect(wr_drain.action.resume_source_read);
    try std.testing.expect(lifecycle.canReadSource(.client_to_target));

    try lifecycle.abort(&pool);
    try std.testing.expectEqual(@as(usize, 5), pool.available());
}
