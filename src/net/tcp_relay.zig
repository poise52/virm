const std = @import("std");
const darwin = @import("../platform/darwin.zig");
const kqueue_reactor = @import("kqueue_reactor.zig");
const buffer_pool = @import("buffer_pool.zig");
const fifo_queue = @import("fifo_queue.zig");
const tcp_lifecycle = @import("tcp_lifecycle.zig");

const KqueueReactor = kqueue_reactor.KqueueReactor;
const WorkerBufferPool = buffer_pool.WorkerBufferPool;
const Buffer = buffer_pool.Buffer;
const TcpLifecycle = tcp_lifecycle.TcpLifecycle;
const Direction = tcp_lifecycle.Direction;
const StreamState = tcp_lifecycle.StreamState;

pub const EventRole = enum(u8) {
    listener = 0,
    client = 1,
    target = 2,
};

/// 64-bit event token stored in kevent udata.
/// Carries role, session generation, and session index to defeat stale events.
pub const EventToken = packed struct(u64) {
    role: EventRole,
    generation: u24,
    session_id: u32,

    pub fn toUdata(self: EventToken) usize {
        return @intCast(@as(u64, @bitCast(self)));
    }

    pub fn fromUdata(udata: usize) EventToken {
        return @bitCast(@as(u64, @intCast(udata)));
    }
};

pub const WaitEntry = struct {
    session_id: u32,
    role: EventRole,
};

/// State of an active bidirectional TCP relay session.
pub const Session = struct {
    id: u32,
    generation: u32,
    is_active: bool,
    client_fd: darwin.fd_t,
    target_fd: darwin.fd_t,
    connect_pending: bool,
    lifecycle: TcpLifecycle,

    client_read_registered: bool = false,
    target_read_registered: bool = false,
    client_write_registered: bool = false,
    target_write_registered: bool = false,

    client_waiting_pool: bool = false,
    target_waiting_pool: bool = false,
    deferred_target_shutdown_wr: bool = false,
};

pub const RelayConfig = struct {
    max_sessions: usize = 128,
    buffer_pool_capacity: usize = 2048,
    default_drain_timeout_ms: i64 = 5000,
    target_addr: darwin.sockaddr_in,
};

/// High-performance, single-worker TCP relay engine using Darwin kqueue.
pub const TcpRelay = struct {
    allocator: std.mem.Allocator,
    reactor: KqueueReactor,
    pool: WorkerBufferPool,
    sessions: []Session,
    wait_queue: std.ArrayList(WaitEntry),
    listener_fd: darwin.fd_t,
    target_addr: darwin.sockaddr_in,
    default_drain_timeout_ms: i64,
    active_sessions_count: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        listener_fd: darwin.fd_t,
        config: RelayConfig,
    ) !TcpRelay {
        var reactor = try KqueueReactor.init();
        errdefer reactor.deinit();

        var pool = try WorkerBufferPool.init(allocator, config.buffer_pool_capacity);
        errdefer pool.deinit(allocator);

        const sessions = try allocator.alloc(Session, config.max_sessions);
        errdefer allocator.free(sessions);

        for (sessions, 0..) |*s, i| {
            s.* = .{
                .id = @intCast(i),
                .generation = 1,
                .is_active = false,
                .client_fd = -1,
                .target_fd = -1,
                .connect_pending = false,
                .lifecycle = TcpLifecycle.init(config.default_drain_timeout_ms),
            };
        }

        const wait_queue = std.ArrayList(WaitEntry).empty;

        var relay = TcpRelay{
            .allocator = allocator,
            .reactor = reactor,
            .pool = pool,
            .sessions = sessions,
            .wait_queue = wait_queue,
            .listener_fd = listener_fd,
            .target_addr = config.target_addr,
            .default_drain_timeout_ms = config.default_drain_timeout_ms,
        };

        // Register listener on reactor
        const listener_token = EventToken{
            .role = .listener,
            .generation = 0,
            .session_id = 0,
        };
        try relay.reactor.setReadInterest(listener_fd, true, listener_token.toUdata());

        return relay;
    }

    pub fn deinit(self: *TcpRelay) void {
        // Abort all active sessions
        for (self.sessions) |*s| {
            if (s.is_active) {
                self.abortSession(s);
            }
        }

        self.reactor.setReadInterest(self.listener_fd, false, 0) catch {};
        self.reactor.deinit();
        self.pool.deinit(self.allocator);
        self.wait_queue.deinit(self.allocator);
        self.allocator.free(self.sessions);
        self.* = undefined;
    }

    /// Allocates an unused session slot.
    fn allocateSession(self: *TcpRelay) ?*Session {
        for (self.sessions) |*s| {
            if (!s.is_active) {
                s.is_active = true;
                s.connect_pending = false;
                s.client_read_registered = false;
                s.target_read_registered = false;
                s.client_write_registered = false;
                s.target_write_registered = false;
                s.client_waiting_pool = false;
                s.target_waiting_pool = false;
                s.deferred_target_shutdown_wr = false;
                s.lifecycle = TcpLifecycle.init(self.default_drain_timeout_ms);
                self.active_sessions_count += 1;
                return s;
            }
        }
        return null;
    }

    fn updateClientReadInterest(self: *TcpRelay, s: *Session, enable: bool) !void {
        if (s.client_read_registered == enable) return;
        const token = EventToken{
            .role = .client,
            .generation = @intCast(s.generation & 0xFFFFFF),
            .session_id = s.id,
        };
        try self.reactor.setReadInterest(s.client_fd, enable, token.toUdata());
        s.client_read_registered = enable;
    }

    fn updateTargetReadInterest(self: *TcpRelay, s: *Session, enable: bool) !void {
        if (s.target_read_registered == enable) return;
        const token = EventToken{
            .role = .target,
            .generation = @intCast(s.generation & 0xFFFFFF),
            .session_id = s.id,
        };
        try self.reactor.setReadInterest(s.target_fd, enable, token.toUdata());
        s.target_read_registered = enable;
    }

    fn updateClientWriteInterest(self: *TcpRelay, s: *Session, enable: bool) !void {
        if (s.client_write_registered == enable) return;
        const token = EventToken{
            .role = .client,
            .generation = @intCast(s.generation & 0xFFFFFF),
            .session_id = s.id,
        };
        try self.reactor.setWriteInterest(s.client_fd, enable, token.toUdata());
        s.client_write_registered = enable;
    }

    fn updateTargetWriteInterest(self: *TcpRelay, s: *Session, enable: bool) !void {
        if (s.target_write_registered == enable) return;
        const token = EventToken{
            .role = .target,
            .generation = @intCast(s.generation & 0xFFFFFF),
            .session_id = s.id,
        };
        try self.reactor.setWriteInterest(s.target_fd, enable, token.toUdata());
        s.target_write_registered = enable;
    }

    /// Abortively cleans up and terminates a session.
    pub fn abortSession(self: *TcpRelay, s: *Session) void {
        if (!s.is_active) return;

        if (s.client_read_registered) self.reactor.unregister(s.client_fd, darwin.EVFILT_READ);
        if (s.client_write_registered) self.reactor.unregister(s.client_fd, darwin.EVFILT_WRITE);
        if (s.target_read_registered) self.reactor.unregister(s.target_fd, darwin.EVFILT_READ);
        if (s.target_write_registered) self.reactor.unregister(s.target_fd, darwin.EVFILT_WRITE);

        if (s.client_fd >= 0) darwin.closeSocket(s.client_fd);
        if (s.target_fd >= 0) darwin.closeSocket(s.target_fd);
        s.client_fd = -1;
        s.target_fd = -1;

        s.lifecycle.abort(&self.pool) catch {};

        s.is_active = false;
        s.client_read_registered = false;
        s.target_read_registered = false;
        s.client_write_registered = false;
        s.target_write_registered = false;
        s.client_waiting_pool = false;
        s.target_waiting_pool = false;
        s.deferred_target_shutdown_wr = false;

        // Clean up any remaining wait queue entries for this session
        var i: usize = 0;
        while (i < self.wait_queue.items.len) {
            if (self.wait_queue.items[i].session_id == s.id) {
                _ = self.wait_queue.orderedRemove(i);
            } else {
                i += 1;
            }
        }

        s.generation +%= 1;
        if (s.generation == 0) s.generation = 1;

        if (self.active_sessions_count > 0) {
            self.active_sessions_count -= 1;
        }

        self.wakeWaitQueue();
    }

    /// Gracefully closes a session whose both directions have finished.
    pub fn finishSession(self: *TcpRelay, s: *Session) void {
        if (!s.is_active) return;

        if (s.client_read_registered) self.reactor.unregister(s.client_fd, darwin.EVFILT_READ);
        if (s.client_write_registered) self.reactor.unregister(s.client_fd, darwin.EVFILT_WRITE);
        if (s.target_read_registered) self.reactor.unregister(s.target_fd, darwin.EVFILT_READ);
        if (s.target_write_registered) self.reactor.unregister(s.target_fd, darwin.EVFILT_WRITE);

        if (s.client_fd >= 0) darwin.closeSocket(s.client_fd);
        if (s.target_fd >= 0) darwin.closeSocket(s.target_fd);
        s.client_fd = -1;
        s.target_fd = -1;

        s.is_active = false;
        s.client_read_registered = false;
        s.target_read_registered = false;
        s.client_write_registered = false;
        s.target_write_registered = false;
        s.client_waiting_pool = false;
        s.target_waiting_pool = false;
        s.deferred_target_shutdown_wr = false;

        // Clean up any remaining wait queue entries for this session
        var i: usize = 0;
        while (i < self.wait_queue.items.len) {
            if (self.wait_queue.items[i].session_id == s.id) {
                _ = self.wait_queue.orderedRemove(i);
            } else {
                i += 1;
            }
        }

        s.generation +%= 1;
        if (s.generation == 0) s.generation = 1;

        if (self.active_sessions_count > 0) {
            self.active_sessions_count -= 1;
        }

        self.wakeWaitQueue();
    }

    /// Wakes up sessions paused due to buffer pool exhaustion when a buffer is returned.
    fn wakeWaitQueue(self: *TcpRelay) void {
        while (self.pool.available() > 0 and self.wait_queue.items.len > 0) {
            const entry = self.wait_queue.orderedRemove(0);
            if (entry.session_id >= self.sessions.len) continue;
            const s = &self.sessions[entry.session_id];
            if (!s.is_active) continue;

            switch (entry.role) {
                .client => {
                    if (s.client_waiting_pool) {
                        s.client_waiting_pool = false;
                        if (s.lifecycle.canReadSource(.client_to_target)) {
                            self.updateClientReadInterest(s, true) catch {
                                self.abortSession(s);
                            };
                        }
                    }
                },
                .target => {
                    if (s.target_waiting_pool) {
                        s.target_waiting_pool = false;
                        if (s.lifecycle.canReadSource(.target_to_client)) {
                            self.updateTargetReadInterest(s, true) catch {
                                self.abortSession(s);
                            };
                        }
                    }
                },
                .listener => {},
            }
        }
    }

    /// Handles new incoming connection from listener.
    fn handleAccept(self: *TcpRelay) void {
        while (true) {
            const acc_res = darwin.acceptNonBlocking(self.listener_fd) catch break;
            const client_fd = switch (acc_res) {
                .Ok => |info| info.fd,
                .WouldBlock, .Aborted => break,
            };

            const s = self.allocateSession() orelse {
                darwin.closeSocket(client_fd);
                break;
            };

            const target_fd = darwin.createNonBlockingTcpSocket() catch {
                darwin.closeSocket(client_fd);
                s.is_active = false;
                self.active_sessions_count -= 1;
                break;
            };

            s.client_fd = client_fd;
            s.target_fd = target_fd;

            // Start nonblocking connect to target
            const conn_res = darwin.connectNonBlocking(target_fd, self.target_addr) catch {
                self.abortSession(s);
                continue;
            };

            switch (conn_res) {
                .Connected => {
                    s.connect_pending = false;
                    self.updateClientReadInterest(s, true) catch {
                        self.abortSession(s);
                        continue;
                    };
                    self.updateTargetReadInterest(s, true) catch {
                        self.abortSession(s);
                        continue;
                    };
                },
                .InProgress => {
                    s.connect_pending = true;
                    // Register write interest on target to detect connect completion
                    self.updateTargetWriteInterest(s, true) catch {
                        self.abortSession(s);
                        continue;
                    };
                    // Client can start reading immediately
                    self.updateClientReadInterest(s, true) catch {
                        self.abortSession(s);
                        continue;
                    };
                },
            }
        }
    }

    fn handleEof(self: *TcpRelay, s: *Session, dir: Direction, now_ms: i64) void {
        const action = s.lifecycle.onSourceEof(dir, now_ms);
        switch (dir) {
            .client_to_target => {
                self.updateClientReadInterest(s, false) catch {};
                if (action.shutdown_dest_write) {
                    if (s.connect_pending) {
                        // Defer SHUT_WR and retain EVFILT_WRITE until async connect finishes
                        s.deferred_target_shutdown_wr = true;
                    } else {
                        darwin.shutdownSocket(s.target_fd, darwin.SHUT_WR);
                        self.updateTargetWriteInterest(s, false) catch {};
                    }
                }
            },
            .target_to_client => {
                self.updateTargetReadInterest(s, false) catch {};
                if (action.shutdown_dest_write) {
                    darwin.shutdownSocket(s.client_fd, darwin.SHUT_WR);
                    self.updateClientWriteInterest(s, false) catch {};
                }
            },
        }

        if (action.session_terminated) {
            self.finishSession(s);
        }
    }

    fn handleRead(self: *TcpRelay, s: *Session, dir: Direction, event_flags: u16, now_ms: i64) void {
        const src_fd = if (dir == .client_to_target) s.client_fd else s.target_fd;

        // 1. Check backpressure flow control
        if (!s.lifecycle.canReadSource(dir)) {
            if (dir == .client_to_target) {
                self.updateClientReadInterest(s, false) catch {};
            } else {
                self.updateTargetReadInterest(s, false) catch {};
            }
            return;
        }

        // 2. Pre-read buffer acquisition
        const buf = self.pool.acquire() orelse {
            // Buffer pool exhausted: pause read and enqueue in wait_queue
            if (dir == .client_to_target) {
                self.updateClientReadInterest(s, false) catch {};
                if (!s.client_waiting_pool) {
                    s.client_waiting_pool = true;
                    self.wait_queue.append(self.allocator, .{ .session_id = s.id, .role = .client }) catch {
                        self.abortSession(s);
                        return;
                    };
                }
            } else {
                self.updateTargetReadInterest(s, false) catch {};
                if (!s.target_waiting_pool) {
                    s.target_waiting_pool = true;
                    self.wait_queue.append(self.allocator, .{ .session_id = s.id, .role = .target }) catch {
                        self.abortSession(s);
                        return;
                    };
                }
            }
            return;
        };

        // 3. Nonblocking read
        const read_res = darwin.readSocket(src_fd, buf.memory[0..buffer_pool.BUFFER_SIZE]) catch {
            self.pool.release(buf) catch {};
            self.abortSession(s);
            return;
        };

        switch (read_res) {
            .Ok => |len| {
                const action = s.lifecycle.onDataRead(dir, buf, len) catch {
                    self.pool.release(buf) catch {};
                    self.abortSession(s);
                    return;
                };

                if (dir == .client_to_target) {
                    if (action.register_dest_write and !s.connect_pending) {
                        self.updateTargetWriteInterest(s, true) catch {
                            self.abortSession(s);
                            return;
                        };
                    }
                    if (action.unregister_source_read) {
                        self.updateClientReadInterest(s, false) catch {};
                    }
                } else {
                    if (action.register_dest_write) {
                        self.updateClientWriteInterest(s, true) catch {
                            self.abortSession(s);
                            return;
                        };
                    }
                    if (action.unregister_source_read) {
                        self.updateTargetReadInterest(s, false) catch {};
                    }
                }
            },
            .WouldBlock => {
                self.pool.release(buf) catch {};
                // If EV_EOF was set and read returned WouldBlock, no more data remains in kernel
                if (event_flags & darwin.EV_EOF != 0) {
                    self.handleEof(s, dir, now_ms);
                }
            },
            .Eof => {
                self.pool.release(buf) catch {};
                self.handleEof(s, dir, now_ms);
            },
            .Reset => {
                self.pool.release(buf) catch {};
                self.abortSession(s);
            },
        }
    }

    fn handleWrite(self: *TcpRelay, s: *Session, dir: Direction) void {
        const dest_fd = if (dir == .client_to_target) s.target_fd else s.client_fd;

        // If outbound connect was pending on target:
        if (dir == .client_to_target and s.connect_pending) {
            const connected = darwin.checkSocketConnected(dest_fd) catch false;
            if (!connected) {
                self.abortSession(s);
                return;
            }
            s.connect_pending = false;
            self.updateTargetReadInterest(s, true) catch {
                self.abortSession(s);
                return;
            };

            // If an empty client EOF arrived while connect was pending, apply deferred SHUT_WR now
            if (s.deferred_target_shutdown_wr) {
                s.deferred_target_shutdown_wr = false;
                darwin.shutdownSocket(dest_fd, darwin.SHUT_WR);
                self.updateTargetWriteInterest(s, false) catch {};
                return;
            }

            // If queue is empty, turn off write interest to prevent busy loop
            if (!s.lifecycle.canWriteDest(.client_to_target)) {
                self.updateTargetWriteInterest(s, false) catch {};
                return;
            }
        }

        const q_idx = @intFromEnum(dir);
        const slice = s.lifecycle.queues[q_idx].peek() orelse {
            // Queue is empty: turn off write interest to avoid busy looping
            if (dir == .client_to_target) {
                self.updateTargetWriteInterest(s, false) catch {};
            } else {
                self.updateClientWriteInterest(s, false) catch {};
            }
            return;
        };

        const write_res = darwin.writeSocket(dest_fd, slice) catch {
            self.abortSession(s);
            return;
        };

        switch (write_res) {
            .Ok => |written| {
                if (written > 0) {
                    const wr = s.lifecycle.onDestWrite(dir, written) catch {
                        self.abortSession(s);
                        return;
                    };

                    if (wr.consumed_buf) |c_buf| {
                        self.pool.release(c_buf) catch {};
                        self.wakeWaitQueue();
                        if (!s.is_active) return;
                    }

                    if (wr.action.resume_source_read) {
                        if (dir == .client_to_target and !s.client_waiting_pool) {
                            self.updateClientReadInterest(s, true) catch {
                                self.abortSession(s);
                                return;
                            };
                        } else if (dir == .target_to_client and !s.target_waiting_pool) {
                            self.updateTargetReadInterest(s, true) catch {
                                self.abortSession(s);
                                return;
                            };
                        }
                    }

                    if (wr.action.shutdown_dest_write) {
                        darwin.shutdownSocket(dest_fd, darwin.SHUT_WR);
                        if (dir == .client_to_target) {
                            self.updateTargetWriteInterest(s, false) catch {};
                        } else {
                            self.updateClientWriteInterest(s, false) catch {};
                        }
                    } else if (!s.lifecycle.canWriteDest(dir)) {
                        if (dir == .client_to_target) {
                            self.updateTargetWriteInterest(s, false) catch {};
                        } else {
                            self.updateClientWriteInterest(s, false) catch {};
                        }
                    }

                    if (wr.action.session_terminated) {
                        self.finishSession(s);
                    }
                }
            },
            .WouldBlock => {
                // Socket buffer is full, leave write filter active
            },
            .BrokenPipe, .Reset => {
                self.abortSession(s);
            },
        }
    }

    /// Processes a single kqueue event with stale event and ABA defense.
    /// Returns true if the event was valid and processed; false if discarded as stale.
    pub fn processEvent(self: *TcpRelay, ev: *const darwin.Kevent, now_ms: i64) bool {
        const token = EventToken.fromUdata(ev.udata);

        if (token.role == .listener) {
            if (ev.ident == @as(usize, @intCast(self.listener_fd))) {
                self.handleAccept();
                return true;
            }
            return false;
        }

        // Stale events and ABA defense
        if (token.session_id >= self.sessions.len) return false;
        const s = &self.sessions[token.session_id];
        if (!s.is_active) return false;
        if ((s.generation & 0xFFFFFF) != token.generation) return false;

        const expected_fd = if (token.role == .client) s.client_fd else s.target_fd;
        if (ev.ident != @as(usize, @intCast(expected_fd))) return false;

        if (ev.filter == darwin.EVFILT_READ) {
            const dir: Direction = if (token.role == .client) .client_to_target else .target_to_client;
            self.handleRead(s, dir, ev.flags, now_ms);
            return true;
        } else if (ev.filter == darwin.EVFILT_WRITE) {
            const dir: Direction = if (token.role == .client) .target_to_client else .client_to_target;
            self.handleWrite(s, dir);
            return true;
        }

        return false;
    }

    /// Advances the event loop by one poll cycle.
    /// Caps reactor poll timeout by the nearest pending drain deadline.
    /// Processes up to 64 events and checks drain deadlines.
    pub fn step(self: *TcpRelay, timeout_ms: ?i64) !usize {
        const pre_now_ms = darwin.getMonotonicMs();
        var nearest_deadline_ms: ?i64 = null;
        for (self.sessions) |*s| {
            if (!s.is_active) continue;
            if (s.lifecycle.stream_state[0] == .draining) {
                if (s.lifecycle.drain_deadline_ms[0]) |d_ms| {
                    nearest_deadline_ms = if (nearest_deadline_ms) |nd| @min(nd, d_ms) else d_ms;
                }
            }
            if (s.lifecycle.stream_state[1] == .draining) {
                if (s.lifecycle.drain_deadline_ms[1]) |d_ms| {
                    nearest_deadline_ms = if (nearest_deadline_ms) |nd| @min(nd, d_ms) else d_ms;
                }
            }
        }

        var effective_timeout_ms: ?i64 = timeout_ms;
        if (nearest_deadline_ms) |dead| {
            const time_to_dead = @max(@as(i64, 0), dead - pre_now_ms);
            effective_timeout_ms = if (effective_timeout_ms) |t| @min(t, time_to_dead) else time_to_dead;
        }

        var events: [64]darwin.Kevent = undefined;
        const count = try self.reactor.poll(&events, effective_timeout_ms);

        const now_ms = darwin.getMonotonicMs();

        for (events[0..count]) |*ev| {
            _ = self.processEvent(ev, now_ms);
        }

        // Periodic inspection of drain deadlines
        for (self.sessions) |*s| {
            if (!s.is_active) continue;

            if (s.lifecycle.stream_state[0] == .draining) {
                if (s.lifecycle.checkDrainDeadline(.client_to_target, now_ms, &self.pool) catch false) {
                    self.abortSession(s);
                    continue;
                }
            }

            if (s.lifecycle.stream_state[1] == .draining) {
                if (s.lifecycle.checkDrainDeadline(.target_to_client, now_ms, &self.pool) catch false) {
                    self.abortSession(s);
                    continue;
                }
            }
        }

        return count;
    }
};

const LoopbackTestHarness = struct {
    allocator: std.mem.Allocator,
    target_listener: darwin.fd_t,
    target_port: u16,
    relay_listener: darwin.fd_t,
    relay_port: u16,
    relay: TcpRelay,

    pub fn init(allocator: std.mem.Allocator, pool_capacity: usize, drain_timeout_ms: i64) !LoopbackTestHarness {
        return initWithOptions(allocator, pool_capacity, drain_timeout_ms, null);
    }

    pub fn initWithOptions(
        allocator: std.mem.Allocator,
        pool_capacity: usize,
        drain_timeout_ms: i64,
        target_rcvbuf: ?c_int,
    ) !LoopbackTestHarness {
        // Target server listener
        const target_listener = try darwin.createNonBlockingTcpSocket();
        errdefer darwin.closeSocket(target_listener);
        try darwin.setReuseAddress(target_listener);
        if (target_rcvbuf) |rcvbuf| {
            _ = darwin.setsockopt(target_listener, darwin.SOL_SOCKET, darwin.SO_RCVBUF, @ptrCast(&rcvbuf), @sizeOf(c_int));
        }
        const t_addr = darwin.makeLoopbackAddr(0);
        const b_t = darwin.bind(target_listener, @ptrCast(&t_addr), @sizeOf(darwin.sockaddr_in));
        std.debug.assert(b_t == 0);
        const l_t = darwin.listen(target_listener, 16);
        std.debug.assert(l_t == 0);

        var bound_t: darwin.sockaddr_in = undefined;
        var len_t: darwin.socklen_t = @sizeOf(darwin.sockaddr_in);
        _ = std.c.getsockname(target_listener, @ptrCast(&bound_t), &len_t);
        const target_port = std.mem.bigToNative(u16, bound_t.port);

        // Relay listener
        const relay_listener = try darwin.createNonBlockingTcpSocket();
        errdefer darwin.closeSocket(relay_listener);
        try darwin.setReuseAddress(relay_listener);
        if (target_rcvbuf) |rcvbuf| {
            _ = darwin.setsockopt(relay_listener, darwin.SOL_SOCKET, darwin.SO_RCVBUF, @ptrCast(&rcvbuf), @sizeOf(c_int));
        }
        const r_addr = darwin.makeLoopbackAddr(0);
        const b_r = darwin.bind(relay_listener, @ptrCast(&r_addr), @sizeOf(darwin.sockaddr_in));
        std.debug.assert(b_r == 0);
        const l_r = darwin.listen(relay_listener, 16);
        std.debug.assert(l_r == 0);

        var bound_r: darwin.sockaddr_in = undefined;
        var len_r: darwin.socklen_t = @sizeOf(darwin.sockaddr_in);
        _ = std.c.getsockname(relay_listener, @ptrCast(&bound_r), &len_r);
        const relay_port = std.mem.bigToNative(u16, bound_r.port);

        const config = RelayConfig{
            .max_sessions = 32,
            .buffer_pool_capacity = pool_capacity,
            .default_drain_timeout_ms = drain_timeout_ms,
            .target_addr = darwin.makeLoopbackAddr(target_port),
        };

        const relay = try TcpRelay.init(allocator, relay_listener, config);

        return .{
            .allocator = allocator,
            .target_listener = target_listener,
            .target_port = target_port,
            .relay_listener = relay_listener,
            .relay_port = relay_port,
            .relay = relay,
        };
    }

    pub fn deinit(self: *LoopbackTestHarness) void {
        self.relay.deinit();
        darwin.closeSocket(self.target_listener);
        darwin.closeSocket(self.relay_listener);
    }

    pub fn acceptTarget(self: *LoopbackTestHarness) !darwin.fd_t {
        var attempts: usize = 0;
        while (attempts < 50) : (attempts += 1) {
            _ = try self.relay.step(2);
            const acc_res = try darwin.acceptNonBlocking(self.target_listener);
            switch (acc_res) {
                .Ok => |info| return info.fd,
                .WouldBlock => darwin.sleepMs(2),
                .Aborted => return error.ConnectionAborted,
            }
        }
        return error.TargetAcceptTimeout;
    }

    pub fn connectClient(self: *LoopbackTestHarness) !darwin.fd_t {
        const client = try darwin.createNonBlockingTcpSocket();
        errdefer darwin.closeSocket(client);
        _ = try darwin.connectNonBlocking(client, darwin.makeLoopbackAddr(self.relay_port));
        return client;
    }

    pub fn pump(self: *LoopbackTestHarness, iterations: usize) !void {
        var i: usize = 0;
        while (i < iterations) : (i += 1) {
            _ = try self.relay.step(2);
        }
    }
};

fn readExact(fd: darwin.fd_t, out_buf: []u8) !void {
    var total: usize = 0;
    var attempts: usize = 0;
    while (total < out_buf.len and attempts < 100) : (attempts += 1) {
        const res = try darwin.readSocket(fd, out_buf[total..]);
        switch (res) {
            .Ok => |n| {
                total += n;
                attempts = 0;
            },
            .WouldBlock => darwin.sleepMs(2),
            .Eof => break,
            .Reset => return error.ConnectionReset,
        }
    }
    if (total != out_buf.len) return error.IncompleteRead;
}

test "TcpRelay bidirectional data transfer with exact byte match" {
    const allocator = std.testing.allocator;
    var harness = try LoopbackTestHarness.init(allocator, 16, 5000);
    defer harness.deinit();

    const client_fd = try harness.connectClient();
    defer darwin.closeSocket(client_fd);

    const target_conn = try harness.acceptTarget();
    defer darwin.closeSocket(target_conn);

    // 1. Client -> Relay -> Target
    const req_payload = "CLIENT_REQ_HELLO_VIRUS_OR_DATA_1234567890";
    _ = try darwin.writeSocket(client_fd, req_payload);

    try harness.pump(5);

    var target_rx: [req_payload.len]u8 = undefined;
    try readExact(target_conn, &target_rx);
    try std.testing.expectEqualStrings(req_payload, &target_rx);

    // 2. Target -> Relay -> Client
    const resp_payload = "TARGET_RESP_WORLD_PROVED_VIRUS_OK_0987654321";
    _ = try darwin.writeSocket(target_conn, resp_payload);

    try harness.pump(5);

    var client_rx: [resp_payload.len]u8 = undefined;
    try readExact(client_fd, &client_rx);
    try std.testing.expectEqualStrings(resp_payload, &client_rx);
}

test "TcpRelay client-first EOF delivers full tail before close" {
    const allocator = std.testing.allocator;
    var harness = try LoopbackTestHarness.init(allocator, 16, 5000);
    defer harness.deinit();

    const client_fd = try harness.connectClient();
    defer darwin.closeSocket(client_fd);

    const target_conn = try harness.acceptTarget();
    defer darwin.closeSocket(target_conn);

    // Client sends request and immediately issues SHUT_WR (client-first EOF)
    const req = "PING_REQUEST_EOF";
    _ = try darwin.writeSocket(client_fd, req);
    darwin.shutdownSocket(client_fd, darwin.SHUT_WR);

    try harness.pump(5);

    // Target receives full request data
    var target_rx: [req.len]u8 = undefined;
    try readExact(target_conn, &target_rx);
    try std.testing.expectEqualStrings(req, &target_rx);

    // Target receives EOF
    var eof_buf: [4]u8 = undefined;
    const eof_res = try darwin.readSocket(target_conn, &eof_buf);
    try std.testing.expectEqual(darwin.ReadResult.Eof, eof_res);

    // Target is still able to send back full response!
    const resp = "PONG_RESPONSE_FINAL";
    _ = try darwin.writeSocket(target_conn, resp);
    darwin.shutdownSocket(target_conn, darwin.SHUT_WR);

    try harness.pump(10);

    // Client receives full response
    var client_rx: [resp.len]u8 = undefined;
    try readExact(client_fd, &client_rx);
    try std.testing.expectEqualStrings(resp, &client_rx);

    try harness.pump(10);
    try std.testing.expectEqual(@as(usize, 0), harness.relay.active_sessions_count);
}

test "TcpRelay server-first EOF delivers full tail to slow client" {
    const allocator = std.testing.allocator;
    var harness = try LoopbackTestHarness.init(allocator, 16, 5000);
    defer harness.deinit();

    const client_fd = try harness.connectClient();
    defer darwin.closeSocket(client_fd);

    const target_conn = try harness.acceptTarget();
    defer darwin.closeSocket(target_conn);

    // Target sends response and immediately issues SHUT_WR (server-first EOF)
    const big_resp = "SERVER_FIRST_FIN_RESPONSE_TAIL_MUST_NOT_BE_DROPPED_AT_ALL";
    _ = try darwin.writeSocket(target_conn, big_resp);
    darwin.shutdownSocket(target_conn, darwin.SHUT_WR);

    try harness.pump(5);

    // Slow client reads 4 bytes at a time
    var client_rx: [big_resp.len]u8 = undefined;
    var offset: usize = 0;
    while (offset < big_resp.len) {
        try harness.pump(2);
        const chunk_size = @min(4, big_resp.len - offset);
        var chunk: [4]u8 = undefined;
        const res = try darwin.readSocket(client_fd, chunk[0..chunk_size]);
        switch (res) {
            .Ok => |n| {
                @memcpy(client_rx[offset .. offset + n], chunk[0..n]);
                offset += n;
            },
            .WouldBlock => darwin.sleepMs(2),
            else => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expectEqualStrings(big_resp, &client_rx);

    // Client sends its EOF
    darwin.shutdownSocket(client_fd, darwin.SHUT_WR);
    try harness.pump(10);

    try std.testing.expectEqual(@as(usize, 0), harness.relay.active_sessions_count);
}

fn countOpenFds() usize {
    var count: usize = 0;
    var fd: darwin.fd_t = 0;
    while (fd < 1024) : (fd += 1) {
        if (darwin.fcntl(fd, darwin.F_GETFD) >= 0) {
            count += 1;
        }
    }
    return count;
}

test "TcpRelay slow reader backpressure, partial write, and byte-exact verification" {
    const allocator = std.testing.allocator;
    // Set small target receive buffer (16 KiB) to deterministically saturate kernel socket buffer
    var harness = try LoopbackTestHarness.initWithOptions(allocator, 16, 5000, 16 * 1024);
    defer harness.deinit();

    const client_fd = try harness.connectClient();
    defer darwin.closeSocket(client_fd);
    const small_snd: c_int = 16 * 1024;
    _ = darwin.setsockopt(client_fd, darwin.SOL_SOCKET, darwin.SO_SNDBUF, @ptrCast(&small_snd), @sizeOf(c_int));

    const target_conn = try harness.acceptTarget();
    defer darwin.closeSocket(target_conn);

    const s = &harness.relay.sessions[0];

    // Overall test deadline to prevent hangs
    const test_deadline = darwin.getMonotonicMs() + 10000;

    // Prepare a deterministic test payload (1 MiB) to reliably saturate socket buffers across build modes
    const payload_size = 1024 * 1024;
    const test_payload = try allocator.alloc(u8, payload_size);
    defer allocator.free(test_payload);
    for (test_payload, 0..) |*b, idx| {
        b.* = @intCast(idx % 251);
    }

    // Client feeds data in increments up to 16 KiB until relay queue throttles reader
    var client_sent: usize = 0;
    var saw_short_write = false;
    var saw_eagain = false;

    while (client_sent < test_payload.len) {
        if (darwin.getMonotonicMs() > test_deadline) return error.TestTimeout;

        if (s.lifecycle.queues[0].shouldThrottleReader()) {
            break;
        }

        const chunk_size = @min(@as(usize, 16 * 1024), test_payload.len - client_sent);
        const wr = try darwin.writeSocket(client_fd, test_payload[client_sent .. client_sent + chunk_size]);
        switch (wr) {
            .Ok => |n| {
                if (n < chunk_size) saw_short_write = true;
                client_sent += n;
            },
            .WouldBlock => {
                saw_eagain = true;
                darwin.sleepMs(1);
            },
            else => break,
        }
        _ = try harness.relay.step(1);
    }

    // 1. Relay queue MUST be throttled
    try std.testing.expect(s.lifecycle.queues[0].shouldThrottleReader());
    try std.testing.expect(!s.lifecycle.canReadSource(.client_to_target));

    // 2. Client read interest MUST be disabled in reactor
    try std.testing.expect(!s.client_read_registered);

    // 3. Client continues writing from test_payload until kernel send buffer fills (EAGAIN/WouldBlock)
    while (client_sent < test_payload.len and darwin.getMonotonicMs() <= test_deadline) {
        const chunk_size = @min(@as(usize, 3500), test_payload.len - client_sent);
        const wr = try darwin.writeSocket(client_fd, test_payload[client_sent .. client_sent + chunk_size]);
        switch (wr) {
            .Ok => |n| {
                if (n < chunk_size) saw_short_write = true;
                client_sent += n;
            },
            .WouldBlock => {
                saw_eagain = true;
                break;
            },
            else => break,
        }
    }
    try std.testing.expect(saw_eagain);

    // 4. While throttled, relay pump MUST NOT read more from client
    try harness.pump(2);
    try std.testing.expect(!s.client_read_registered);

    // 5. Target slowly drains data in 2 KiB chunks
    const received_data = try allocator.alloc(u8, client_sent);
    defer allocator.free(received_data);

    var target_read_total: usize = 0;
    var drain_buf: [2048]u8 = undefined;
    var saw_read_resumed = false;

    while (target_read_total < client_sent) {
        if (darwin.getMonotonicMs() > test_deadline) return error.TestTimeout;
        try harness.pump(1);

        const r_res = try darwin.readSocket(target_conn, &drain_buf);
        switch (r_res) {
            .Ok => |n| {
                @memcpy(received_data[target_read_total .. target_read_total + n], drain_buf[0..n]);
                target_read_total += n;
                if (s.client_read_registered) {
                    saw_read_resumed = true;
                }
            },
            .WouldBlock => darwin.sleepMs(1),
            else => break,
        }
    }

    // 6. Full byte-exact verification
    try std.testing.expectEqual(client_sent, target_read_total);
    try std.testing.expect(saw_read_resumed);
    try std.testing.expect(saw_short_write);
    try std.testing.expect(saw_eagain);
    try std.testing.expectEqualSlices(u8, test_payload[0..client_sent], received_data[0..target_read_total]);
}

const ReviewFixture = struct {
    target_listener: darwin.fd_t,
    listener: darwin.fd_t,
    client: darwin.fd_t,
    target: darwin.fd_t,
    relay: TcpRelay,

    fn listenerSocket() !struct { fd: darwin.fd_t, port: u16 } {
        const fd = try darwin.createNonBlockingTcpSocket();
        errdefer darwin.closeSocket(fd);
        const addr = darwin.makeLoopbackAddr(0);
        if (darwin.bind(fd, @ptrCast(&addr), @sizeOf(darwin.sockaddr_in)) != 0) return error.BindFailed;
        if (darwin.listen(fd, 16) != 0) return error.ListenFailed;
        var actual: darwin.sockaddr_in = undefined;
        var len: darwin.socklen_t = @sizeOf(darwin.sockaddr_in);
        if (std.c.getsockname(fd, @ptrCast(&actual), &len) != 0) return error.GetSockNameFailed;
        return .{ .fd = fd, .port = std.mem.bigToNative(u16, actual.port) };
    }

    fn init(a: std.mem.Allocator, capacity: usize, timeout: i64) !ReviewFixture {
        const tl = try listenerSocket();
        errdefer darwin.closeSocket(tl.fd);
        const l = try listenerSocket();
        errdefer darwin.closeSocket(l.fd);
        var relay = try TcpRelay.init(a, l.fd, .{
            .max_sessions = 4,
            .buffer_pool_capacity = capacity,
            .default_drain_timeout_ms = timeout,
            .target_addr = darwin.makeLoopbackAddr(tl.port),
        });
        errdefer relay.deinit();
        const client = try darwin.createNonBlockingTcpSocket();
        errdefer darwin.closeSocket(client);
        _ = try darwin.connectNonBlocking(client, darwin.makeLoopbackAddr(l.port));
        var target: ?darwin.fd_t = null;
        for (0..50) |_| {
            _ = try relay.step(1);
            const ar = try darwin.acceptNonBlocking(tl.fd);
            if (ar == .Ok) {
                target = ar.Ok.fd;
                break;
            }
        }
        const target_fd = target orelse return error.TargetAcceptTimeout;
        errdefer darwin.closeSocket(target_fd);
        for (0..10) |_| {
            _ = try relay.step(1);
        }
        try std.testing.expect(relay.sessions[0].is_active);
        try std.testing.expect(!relay.sessions[0].connect_pending);
        return .{ .target_listener = tl.fd, .listener = l.fd, .client = client, .target = target_fd, .relay = relay };
    }

    fn deinit(f: *ReviewFixture) void {
        f.relay.deinit();
        darwin.closeSocket(f.client);
        darwin.closeSocket(f.target);
        darwin.closeSocket(f.listener);
        darwin.closeSocket(f.target_listener);
    }
};

test "TcpRelay review regression: drain deadline caps poll wait" {
    var f = try ReviewFixture.init(std.testing.allocator, 8, 30);
    defer f.deinit();
    const s = &f.relay.sessions[0];
    const b = f.relay.pool.acquire().?;
    b.memory[0] = 'X';
    try s.lifecycle.queues[0].push(b, 1);
    s.lifecycle.stream_state[0] = .draining;
    const start = darwin.getMonotonicMs();
    s.lifecycle.drain_deadline_ms[0] = start + 30;
    _ = try f.relay.step(200);
    const elapsed = darwin.getMonotonicMs() - start;
    try std.testing.expect(elapsed < 100);
    try std.testing.expectEqual(@as(usize, 0), f.relay.active_sessions_count);
}

test "TcpRelay review regression: pool wait enqueue OOM must not orphan active session" {
    var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var f = try ReviewFixture.init(fa.allocator(), 1, 5000);
    defer f.deinit();
    const held = f.relay.pool.acquire().?;
    defer f.relay.pool.release(held) catch unreachable;
    fa.fail_index = fa.alloc_index;
    const wr = try darwin.writeSocket(f.client, "X");
    try std.testing.expect(wr == .Ok);
    for (0..3) |_| {
        _ = try f.relay.step(1);
    }
    const s = &f.relay.sessions[0];
    try std.testing.expect(fa.has_induced_failure);
    try std.testing.expect(!s.is_active or f.relay.wait_queue.items.len > 0);
}

test "TcpRelay review regression: empty client EOF must preserve pending connect completion" {
    var f = try ReviewFixture.init(std.testing.allocator, 8, 50);
    defer f.deinit();
    const s = &f.relay.sessions[0];
    s.connect_pending = true;
    f.relay.reactor.unregister(s.target_fd, darwin.EVFILT_READ);
    s.target_read_registered = false;
    const token = EventToken{ .role = .target, .generation = @intCast(s.generation & 0xFFFFFF), .session_id = s.id };
    try f.relay.reactor.register(s.target_fd, darwin.EVFILT_WRITE, darwin.EV_ADD | darwin.EV_DISABLE, token.toUdata());
    s.target_write_registered = true;
    darwin.shutdownSocket(f.client, darwin.SHUT_WR);
    _ = try f.relay.step(10);
    try std.testing.expect(!s.is_active or !s.connect_pending or s.target_write_registered);
}

test "TcpRelay review regression: null poll timeout is capped by drain deadline" {
    var f = try ReviewFixture.init(std.testing.allocator, 8, 30);
    defer f.deinit();
    const s = &f.relay.sessions[0];
    const b = f.relay.pool.acquire().?;
    b.memory[0] = 'X';
    try s.lifecycle.queues[0].push(b, 1);
    s.lifecycle.stream_state[0] = .draining;
    const start = darwin.getMonotonicMs();
    s.lifecycle.drain_deadline_ms[0] = start + 30;
    _ = try f.relay.step(null);
    const elapsed = darwin.getMonotonicMs() - start;
    try std.testing.expect(elapsed < 100);
    try std.testing.expectEqual(@as(usize, 0), f.relay.active_sessions_count);
}

test "TcpRelay review regression: deferred EOF completes connect and permits target reply" {
    var f = try ReviewFixture.init(std.testing.allocator, 8, 50);
    defer f.deinit();
    const s = &f.relay.sessions[0];
    s.connect_pending = true;
    f.relay.reactor.unregister(s.target_fd, darwin.EVFILT_READ);
    s.target_read_registered = false;
    const token = EventToken{ .role = .target, .generation = @intCast(s.generation & 0xFFFFFF), .session_id = s.id };
    try f.relay.reactor.register(s.target_fd, darwin.EVFILT_WRITE, darwin.EV_ADD | darwin.EV_DISABLE, token.toUdata());
    s.target_write_registered = true;
    darwin.shutdownSocket(f.client, darwin.SHUT_WR);
    _ = try f.relay.step(10);
    try std.testing.expect(s.deferred_target_shutdown_wr);
    const completion = darwin.Kevent{ .ident = @intCast(s.target_fd), .filter = darwin.EVFILT_WRITE, .flags = 0, .fflags = 0, .data = 0, .udata = token.toUdata() };
    try std.testing.expect(f.relay.processEvent(&completion, darwin.getMonotonicMs()));
    try std.testing.expect(!s.connect_pending);
    try std.testing.expect(!s.deferred_target_shutdown_wr);
    try std.testing.expect(s.target_read_registered);
    var b: [8]u8 = undefined;
    var got_fin = false;
    for (0..50) |_| {
        const rr = try darwin.readSocket(f.target, &b);
        if (rr == .Eof) {
            got_fin = true;
            break;
        }
        try std.testing.expect(rr == .WouldBlock);
        darwin.sleepMs(1);
    }
    try std.testing.expect(got_fin);
    const wr = try darwin.writeSocket(f.target, "R");
    try std.testing.expect(wr == .Ok and wr.Ok == 1);
    var received = false;
    for (0..30) |_| {
        _ = try f.relay.step(1);
        const rr = try darwin.readSocket(f.client, &b);
        if (rr == .Ok) {
            try std.testing.expectEqualStrings("R", b[0..rr.Ok]);
            received = true;
            break;
        }
    }
    try std.testing.expect(received);
}

test "TcpRelay review regression: failed mandatory WRITE registration must terminate or retain progress" {
    var f = try ReviewFixture.init(std.testing.allocator, 8, 50);
    defer f.deinit();
    const s = &f.relay.sessions[0];
    const wr = try darwin.writeSocket(f.client, "X");
    try std.testing.expect(wr == .Ok and wr.Ok == 1);
    const token = EventToken{ .role = .client, .generation = @intCast(s.generation & 0xFFFFFF), .session_id = s.id };
    const ev = darwin.Kevent{ .ident = @intCast(s.client_fd), .filter = darwin.EVFILT_READ, .flags = 0, .fflags = 0, .data = 1, .udata = token.toUdata() };
    var ready = false;
    for (0..50) |_| {
        var events: [8]darwin.Kevent = undefined;
        const n = try f.relay.reactor.poll(&events, 5);
        for (events[0..n]) |event| {
            if (event.ident == ev.ident and event.filter == darwin.EVFILT_READ) {
                ready = true;
                break;
            }
        }
        if (ready) break;
    }
    try std.testing.expect(ready);
    const actual_kq = f.relay.reactor.kq_fd;
    f.relay.reactor.kq_fd = -1;
    const processed = f.relay.processEvent(&ev, darwin.getMonotonicMs());
    f.relay.reactor.kq_fd = actual_kq;
    try std.testing.expect(processed);
    if (s.is_active) try std.testing.expectEqual(@as(usize, 1), s.lifecycle.queues[0].pendingBytes());
    for (0..5) |_| {
        _ = try f.relay.step(1);
    }
    try std.testing.expect(!s.is_active or s.target_write_registered or s.lifecycle.queues[0].pendingBytes() == 0);
}

test "TcpRelay review regression: wakeup failure must stop processing an aborted current session (target write / target read wake)" {
    var f = try ReviewFixture.init(std.testing.allocator, 1, 50);
    defer f.deinit();
    const s = &f.relay.sessions[0];
    const b = f.relay.pool.acquire().?;
    b.memory[0] = 'X';
    try s.lifecycle.queues[0].push(b, 1);
    const wr = try darwin.writeSocket(f.target, "Y");
    try std.testing.expect(wr == .Ok and wr.Ok == 1);
    const rt = EventToken{ .role = .target, .generation = @intCast(s.generation & 0xFFFFFF), .session_id = s.id };
    var read_ev: ?darwin.Kevent = null;
    for (0..50) |_| {
        var events: [8]darwin.Kevent = undefined;
        const n = try f.relay.reactor.poll(&events, 5);
        for (events[0..n]) |ev| {
            if (ev.ident == @as(usize, @intCast(s.target_fd)) and ev.filter == darwin.EVFILT_READ) {
                read_ev = ev;
                break;
            }
        }
        if (read_ev != null) break;
    }
    const re = read_ev orelse return error.ReadinessTimeout;
    try std.testing.expect(f.relay.processEvent(&re, darwin.getMonotonicMs()));
    try std.testing.expect(s.target_waiting_pool);
    try std.testing.expect(!s.target_read_registered);
    try std.testing.expectEqual(@as(usize, 1), f.relay.wait_queue.items.len);
    try f.relay.reactor.register(s.target_fd, darwin.EVFILT_WRITE, darwin.EV_ADD | darwin.EV_DISABLE, rt.toUdata());
    s.target_write_registered = true;
    const ev = darwin.Kevent{ .ident = @intCast(s.target_fd), .filter = darwin.EVFILT_WRITE, .flags = 0, .fflags = 0, .data = 1, .udata = rt.toUdata() };
    const actual_kq = f.relay.reactor.kq_fd;
    defer f.relay.reactor.kq_fd = actual_kq;
    f.relay.reactor.kq_fd = -1;
    _ = f.relay.processEvent(&ev, darwin.getMonotonicMs());
    try std.testing.expect(!s.is_active);
    try std.testing.expectEqual(@as(usize, 1), f.relay.pool.available());
    try std.testing.expectEqual(@as(usize, 0), f.relay.wait_queue.items.len);
}

test "TcpRelay review regression: wakeup failure must stop processing an aborted current session (symmetric client write / client read wake)" {
    var f = try ReviewFixture.init(std.testing.allocator, 1, 50);
    defer f.deinit();
    const s = &f.relay.sessions[0];
    const b = f.relay.pool.acquire().?;
    b.memory[0] = 'X';
    try s.lifecycle.queues[1].push(b, 1);
    const wr = try darwin.writeSocket(f.client, "Y");
    try std.testing.expect(wr == .Ok and wr.Ok == 1);
    const ct = EventToken{ .role = .client, .generation = @intCast(s.generation & 0xFFFFFF), .session_id = s.id };
    var read_ev: ?darwin.Kevent = null;
    for (0..50) |_| {
        var events: [8]darwin.Kevent = undefined;
        const n = try f.relay.reactor.poll(&events, 5);
        for (events[0..n]) |ev| {
            if (ev.ident == @as(usize, @intCast(s.client_fd)) and ev.filter == darwin.EVFILT_READ) {
                read_ev = ev;
                break;
            }
        }
        if (read_ev != null) break;
    }
    const re = read_ev orelse return error.ReadinessTimeout;
    try std.testing.expect(f.relay.processEvent(&re, darwin.getMonotonicMs()));
    try std.testing.expect(s.client_waiting_pool);
    try std.testing.expect(!s.client_read_registered);
    try std.testing.expectEqual(@as(usize, 1), f.relay.wait_queue.items.len);
    try f.relay.reactor.register(s.client_fd, darwin.EVFILT_WRITE, darwin.EV_ADD | darwin.EV_DISABLE, ct.toUdata());
    s.client_write_registered = true;
    const ev = darwin.Kevent{ .ident = @intCast(s.client_fd), .filter = darwin.EVFILT_WRITE, .flags = 0, .fflags = 0, .data = 1, .udata = ct.toUdata() };
    const actual_kq = f.relay.reactor.kq_fd;
    defer f.relay.reactor.kq_fd = actual_kq;
    f.relay.reactor.kq_fd = -1;
    _ = f.relay.processEvent(&ev, darwin.getMonotonicMs());
    try std.testing.expect(!s.is_active);
    try std.testing.expectEqual(@as(usize, 1), f.relay.pool.available());
    try std.testing.expectEqual(@as(usize, 0), f.relay.wait_queue.items.len);
}

test "TcpRelay buffer pool exhaustion pauses read and resumes on drain" {
    const allocator = std.testing.allocator;
    // Pool of 2 buffers
    var harness = try LoopbackTestHarness.init(allocator, 2, 5000);
    defer harness.deinit();

    const client_fd = try harness.connectClient();
    defer darwin.closeSocket(client_fd);

    const target_conn = try harness.acceptTarget();
    defer darwin.closeSocket(target_conn);

    // Artificially acquire all pool buffers to simulate background worker pool exhaustion
    const b_hold0 = harness.relay.pool.acquire().?;
    const b_hold1 = harness.relay.pool.acquire().?;
    try std.testing.expect(harness.relay.pool.isExhausted());

    // Client sends data while pool is exhausted
    _ = try darwin.writeSocket(client_fd, "POST_EXHAUSTION_DATA");
    try harness.pump(5);

    // Relay must have paused client reading and enqueued it in wait_queue
    try std.testing.expect(harness.relay.wait_queue.items.len > 0);
    try std.testing.expect(harness.relay.sessions[0].client_waiting_pool);

    // Target cannot have received data yet
    var probe_buf: [32]u8 = undefined;
    const probe_res = try darwin.readSocket(target_conn, &probe_buf);
    try std.testing.expectEqual(darwin.ReadResult.WouldBlock, probe_res);

    // Release one buffer back to pool -> triggers wakeWaitQueue
    try harness.relay.pool.release(b_hold0);
    harness.relay.wakeWaitQueue();

    try harness.pump(10);

    // Now POST_EXHAUSTION_DATA has been read and relayed to target!
    var post_buf: [20]u8 = undefined;
    try readExact(target_conn, &post_buf);
    try std.testing.expectEqualStrings("POST_EXHAUSTION_DATA", &post_buf);

    try harness.relay.pool.release(b_hold1);
}

test "TcpRelay drain deadline timeout forces abort and drops buffers" {
    const allocator = std.testing.allocator;
    var harness = try LoopbackTestHarness.init(allocator, 8, 50);
    defer harness.deinit();

    const client_fd = try harness.connectClient();
    defer darwin.closeSocket(client_fd);

    const target_conn = try harness.acceptTarget();
    defer darwin.closeSocket(target_conn);

    try harness.pump(5);
    try std.testing.expectEqual(@as(usize, 1), harness.relay.active_sessions_count);

    // Put session into draining state with pending data in queue
    const s = &harness.relay.sessions[0];
    const b = harness.relay.pool.acquire().?;
    @memcpy(b.memory[0..10], "STALL_DATA");
    try s.lifecycle.queues[0].push(b, 10);
    s.lifecycle.stream_state[0] = .draining;
    s.lifecycle.drain_deadline_ms[0] = darwin.getMonotonicMs() + 50;

    // Target does not drain the queue. Wait for deadline to expire
    darwin.sleepMs(60);

    // Pump relay to process expired deadline check
    try harness.pump(5);

    // Session must be aborted, active count reset to 0, and all 8 buffers returned to pool
    try std.testing.expectEqual(@as(usize, 0), harness.relay.active_sessions_count);
    try std.testing.expectEqual(@as(usize, 8), harness.relay.pool.available());
}

test "TcpRelay stale event token and ABA generation rejection" {
    const allocator = std.testing.allocator;
    var harness = try LoopbackTestHarness.init(allocator, 8, 5000);
    defer harness.deinit();

    const client_fd = try harness.connectClient();
    defer darwin.closeSocket(client_fd);

    const target_conn = try harness.acceptTarget();
    defer darwin.closeSocket(target_conn);

    try harness.pump(5);
    try std.testing.expectEqual(@as(usize, 1), harness.relay.active_sessions_count);

    const s = &harness.relay.sessions[0];
    const real_client_fd = s.client_fd;
    const real_gen = s.generation;
    const now_ms = darwin.getMonotonicMs();

    // 1. Stale session ID out of range
    const bad_id_token = EventToken{ .role = .client, .generation = @intCast(real_gen & 0xFFFFFF), .session_id = 999 };
    const bad_id_ev = darwin.Kevent{
        .ident = @intCast(real_client_fd),
        .filter = darwin.EVFILT_READ,
        .flags = 0,
        .fflags = 0,
        .data = 0,
        .udata = bad_id_token.toUdata(),
    };
    try std.testing.expect(!harness.relay.processEvent(&bad_id_ev, now_ms));

    // 2. Stale generation (ABA attack / delayed event from previous incarnation)
    const stale_gen_token = EventToken{ .role = .client, .generation = @intCast((real_gen + 10) & 0xFFFFFF), .session_id = s.id };
    const stale_gen_ev = darwin.Kevent{
        .ident = @intCast(real_client_fd),
        .filter = darwin.EVFILT_READ,
        .flags = 0,
        .fflags = 0,
        .data = 0,
        .udata = stale_gen_token.toUdata(),
    };
    try std.testing.expect(!harness.relay.processEvent(&stale_gen_ev, now_ms));

    // 3. Reused FD mismatch (ident does not match session client_fd)
    const mismatched_fd_token = EventToken{ .role = .client, .generation = @intCast(real_gen & 0xFFFFFF), .session_id = s.id };
    const mismatched_fd_ev = darwin.Kevent{
        .ident = @intCast(real_client_fd + 100),
        .filter = darwin.EVFILT_READ,
        .flags = 0,
        .fflags = 0,
        .data = 0,
        .udata = mismatched_fd_token.toUdata(),
    };
    try std.testing.expect(!harness.relay.processEvent(&mismatched_fd_ev, now_ms));

    // 4. Inactive session slot rejection
    const inactive_slot = &harness.relay.sessions[1];
    try std.testing.expect(!inactive_slot.is_active);
    const inactive_token = EventToken{ .role = .client, .generation = 1, .session_id = inactive_slot.id };
    const inactive_ev = darwin.Kevent{
        .ident = 10,
        .filter = darwin.EVFILT_READ,
        .flags = 0,
        .fflags = 0,
        .data = 0,
        .udata = inactive_token.toUdata(),
    };
    try std.testing.expect(!harness.relay.processEvent(&inactive_ev, now_ms));
}

test "TcpRelay outbound connect refusal aborts session cleanly" {
    const allocator = std.testing.allocator;

    const relay_listener = try darwin.createNonBlockingTcpSocket();
    defer darwin.closeSocket(relay_listener);
    try darwin.setReuseAddress(relay_listener);
    const r_addr = darwin.makeLoopbackAddr(0);
    _ = darwin.bind(relay_listener, @ptrCast(&r_addr), @sizeOf(darwin.sockaddr_in));
    _ = darwin.listen(relay_listener, 16);

    var bound_r: darwin.sockaddr_in = undefined;
    var len_r: darwin.socklen_t = @sizeOf(darwin.sockaddr_in);
    _ = std.c.getsockname(relay_listener, @ptrCast(&bound_r), &len_r);
    const relay_port = std.mem.bigToNative(u16, bound_r.port);

    // Bind to a temporary port and close immediately to guarantee connection refusal on localhost
    const temp_sock = try darwin.createNonBlockingTcpSocket();
    const temp_addr = darwin.makeLoopbackAddr(0);
    _ = darwin.bind(temp_sock, @ptrCast(&temp_addr), @sizeOf(darwin.sockaddr_in));
    var bound_temp: darwin.sockaddr_in = undefined;
    var len_temp: darwin.socklen_t = @sizeOf(darwin.sockaddr_in);
    _ = std.c.getsockname(temp_sock, @ptrCast(&bound_temp), &len_temp);
    const refused_port = std.mem.bigToNative(u16, bound_temp.port);
    darwin.closeSocket(temp_sock);

    const config = RelayConfig{
        .max_sessions = 8,
        .buffer_pool_capacity = 8,
        .default_drain_timeout_ms = 5000,
        .target_addr = darwin.makeLoopbackAddr(refused_port),
    };

    var relay = try TcpRelay.init(allocator, relay_listener, config);
    defer relay.deinit();

    const client = try darwin.createNonBlockingTcpSocket();
    defer darwin.closeSocket(client);
    _ = try darwin.connectNonBlocking(client, darwin.makeLoopbackAddr(relay_port));

    // Step relay: accept client, attempt async connect to refused port, detect refusal, abort session
    var i: usize = 0;
    while (i < 30) : (i += 1) {
        _ = try relay.step(5);
    }

    try std.testing.expectEqual(@as(usize, 0), relay.active_sessions_count);
    try std.testing.expectEqual(@as(usize, 8), relay.pool.available());
}

test "TcpRelay repeated connection cycles without fd or buffer leaks" {
    const allocator = std.testing.allocator;
    var harness = try LoopbackTestHarness.init(allocator, 8, 5000);
    defer harness.deinit();

    // Baseline count of open file descriptors with relay listener and target listener running
    const initial_fds = countOpenFds();

    var cycle: usize = 0;
    while (cycle < 50) : (cycle += 1) {
        const client_fd = try harness.connectClient();
        const target_conn = try harness.acceptTarget();

        _ = try darwin.writeSocket(client_fd, "PING_CYCLE");
        try harness.pump(5);

        var rx_buf: [10]u8 = undefined;
        try readExact(target_conn, &rx_buf);
        try std.testing.expectEqualStrings("PING_CYCLE", &rx_buf);

        darwin.shutdownSocket(client_fd, darwin.SHUT_WR);
        darwin.shutdownSocket(target_conn, darwin.SHUT_WR);
        try harness.pump(5);

        darwin.closeSocket(client_fd);
        darwin.closeSocket(target_conn);
    }

    // Pump to process any remaining events
    try harness.pump(5);

    const final_fds = countOpenFds();
    try std.testing.expectEqual(initial_fds, final_fds);
    try std.testing.expectEqual(@as(usize, 0), harness.relay.active_sessions_count);
    try std.testing.expectEqual(@as(usize, 8), harness.relay.pool.available());
}
