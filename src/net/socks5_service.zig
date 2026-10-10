//! SOCKS5 Nonblocking Service & TCP Relay Engine
//!
//! Provides an end-to-end event-driven SOCKS5 inbound adapter using Darwin kqueue:
//! accept -> greeting -> CONNECT request -> router evaluation -> Direct connect / Block reply
//! -> reply flush -> bidirectional TCP relay with buffer pool, FIFO queue backpressure,
//! half-close, and bounded monotonic deadlines.

const std = @import("std");
const darwin = @import("../platform/darwin.zig");
const kqueue_reactor = @import("kqueue_reactor.zig");
const buffer_pool = @import("buffer_pool.zig");
const fifo_queue = @import("fifo_queue.zig");
const tcp_lifecycle = @import("tcp_lifecycle.zig");
const socks5 = @import("../protocol/socks5.zig");
const router_mod = @import("../routing/router.zig");

const KqueueReactor = kqueue_reactor.KqueueReactor;
const WorkerBufferPool = buffer_pool.WorkerBufferPool;
const Buffer = buffer_pool.Buffer;
const TcpLifecycle = tcp_lifecycle.TcpLifecycle;
const Direction = tcp_lifecycle.Direction;
const StreamState = tcp_lifecycle.StreamState;
const Socks5Handshake = socks5.Socks5Handshake;
const TargetEndpoint = socks5.TargetEndpoint;
const Router = router_mod.Router;
const OutboundAction = router_mod.OutboundAction;

pub const EventRole = enum(u8) {
    listener = 0,
    client = 1,
    target = 2,
};

/// 64-bit event token stored in kevent udata.
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

pub const SessionPhase = enum {
    idle,
    handshake,
    flushing_method_reply,
    connecting_target,
    flushing_connect_reply,
    flushing_error_reply,
    relay,
};

pub const TransferredSockets = struct {
    client_fd: darwin.fd_t,
    target_fd: darwin.fd_t,
};

/// Pre-relay SOCKS5 adapter managing client negotiation and target connection.
pub const Socks5Adapter = struct {
    client_fd: darwin.fd_t = -1,
    target_fd: darwin.fd_t = -1,
    handshake: Socks5Handshake = .{},
    reply_buf: [262]u8 = undefined,
    reply_len: usize = 0,
    reply_offset: usize = 0,
    handshake_deadline_ms: i64 = 0,
    connect_deadline_ms: ?i64 = null,
    reply_deadline_ms: ?i64 = null,
    early_payload: ?Buffer = null,
    early_payload_len: usize = 0,
    target_endpoint: ?TargetEndpoint = null,
    pending_input: [1024]u8 = undefined,
    pending_input_len: usize = 0,

    /// Relinquishes socket ownership to the active relay session.
    pub fn transferToRelay(self: *Socks5Adapter) TransferredSockets {
        const c_fd = self.client_fd;
        const t_fd = self.target_fd;
        self.client_fd = -1;
        self.target_fd = -1;
        return .{
            .client_fd = c_fd,
            .target_fd = t_fd,
        };
    }

    /// Aborts pre-relay session and safely closes any held file descriptors.
    pub fn abort(self: *Socks5Adapter) void {
        if (self.client_fd >= 0) {
            darwin.closeSocket(self.client_fd);
            self.client_fd = -1;
        }
        if (self.target_fd >= 0) {
            darwin.closeSocket(self.target_fd);
            self.target_fd = -1;
        }
        self.handshake.reset();
        self.reply_len = 0;
        self.reply_offset = 0;
        self.connect_deadline_ms = null;
        self.reply_deadline_ms = null;
        self.target_endpoint = null;
        self.pending_input_len = 0;
    }
};

/// State of an inbound connection.
pub const Session = struct {
    id: u32,
    generation: u32,
    is_active: bool,
    phase: SessionPhase,
    adapter: Socks5Adapter,
    client_fd: darwin.fd_t = -1,
    target_fd: darwin.fd_t = -1,
    lifecycle: TcpLifecycle,

    client_read_registered: bool = false,
    target_read_registered: bool = false,
    client_write_registered: bool = false,
    target_write_registered: bool = false,

    client_waiting_pool: bool = false,
    target_waiting_pool: bool = false,
    deferred_target_shutdown_wr: bool = false,
};

pub const Socks5Config = struct {
    max_sessions: usize = 128,
    buffer_pool_capacity: usize = 2048,
    handshake_timeout_ms: i64 = 10000,
    connect_timeout_ms: i64 = 10000,
    reply_timeout_ms: i64 = 5000,
    drain_timeout_ms: i64 = 5000,
};

fn minDeadline(current: ?i64, candidate: i64) ?i64 {
    if (current) |curr| {
        return @min(curr, candidate);
    }
    return candidate;
}

pub fn mapPlatformErrorToReplyCode(err: anyerror) socks5.ReplyCode {
    return switch (err) {
        darwin.PlatformError.ConnectionRefused => .connection_refused,
        darwin.PlatformError.NetworkUnreachable => .network_unreachable,
        darwin.PlatformError.HostUnreachable, darwin.PlatformError.TimedOut => .host_unreachable,
        else => .general_failure,
    };
}

pub var review_block_reply_write: bool = false;

fn writeReplySocket(fd: darwin.fd_t, data: []const u8) darwin.PlatformError!darwin.WriteResult {
    if (review_block_reply_write) return .WouldBlock;
    return darwin.writeSocket(fd, data);
}

/// SOCKS5 Proxy Service Engine using Darwin kqueue.
pub const Socks5Service = struct {
    allocator: std.mem.Allocator,
    reactor: KqueueReactor,
    pool: WorkerBufferPool,
    sessions: []Session,
    wait_queue: std.ArrayList(WaitEntry),
    listener_fd: darwin.fd_t,
    router: Router,
    config: Socks5Config,
    active_sessions_count: usize = 0,
    in_wake: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        listener_fd: darwin.fd_t,
        router: Router,
        config: Socks5Config,
    ) !Socks5Service {
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
                .phase = .idle,
                .adapter = .{},
                .lifecycle = TcpLifecycle.init(config.drain_timeout_ms),
            };
        }

        var wait_queue: std.ArrayList(WaitEntry) = .empty;
        errdefer wait_queue.deinit(allocator);

        var self = Socks5Service{
            .allocator = allocator,
            .reactor = reactor,
            .pool = pool,
            .sessions = sessions,
            .wait_queue = wait_queue,
            .listener_fd = listener_fd,
            .router = router,
            .config = config,
        };

        const listener_token = EventToken{
            .role = .listener,
            .generation = 0,
            .session_id = 0,
        };
        try self.reactor.setReadInterest(listener_fd, true, listener_token.toUdata());

        return self;
    }

    pub fn deinit(self: *Socks5Service) void {
        for (self.sessions) |*s| {
            if (s.is_active) {
                self.abortSession(s);
            }
        }
        self.reactor.setReadInterest(self.listener_fd, false, 0) catch {};
        self.reactor.deinit();
        self.pool.deinit(self.allocator);
        self.allocator.free(self.sessions);
        self.wait_queue.deinit(self.allocator);
    }

    fn updateClientReadInterest(self: *Socks5Service, s: *Session, enable: bool) !void {
        if (s.client_read_registered == enable) return;
        const fd = if (s.phase == .relay) s.client_fd else s.adapter.client_fd;
        if (fd < 0) return;
        const token = EventToken{ .role = .client, .generation = @truncate(s.generation), .session_id = s.id };
        try self.reactor.setReadInterest(fd, enable, token.toUdata());
        s.client_read_registered = enable;
    }

    fn updateClientWriteInterest(self: *Socks5Service, s: *Session, enable: bool) !void {
        if (s.client_write_registered == enable) return;
        const fd = if (s.phase == .relay) s.client_fd else s.adapter.client_fd;
        if (fd < 0) return;
        const token = EventToken{ .role = .client, .generation = @truncate(s.generation), .session_id = s.id };
        try self.reactor.setWriteInterest(fd, enable, token.toUdata());
        s.client_write_registered = enable;
    }

    fn updateTargetReadInterest(self: *Socks5Service, s: *Session, enable: bool) !void {
        if (s.target_read_registered == enable) return;
        const fd = if (s.phase == .relay) s.target_fd else s.adapter.target_fd;
        if (fd < 0) return;
        const token = EventToken{ .role = .target, .generation = @truncate(s.generation), .session_id = s.id };
        try self.reactor.setReadInterest(fd, enable, token.toUdata());
        s.target_read_registered = enable;
    }

    fn updateTargetWriteInterest(self: *Socks5Service, s: *Session, enable: bool) !void {
        if (s.target_write_registered == enable) return;
        const fd = if (s.phase == .relay) s.target_fd else s.adapter.target_fd;
        if (fd < 0) return;
        const token = EventToken{ .role = .target, .generation = @truncate(s.generation), .session_id = s.id };
        try self.reactor.setWriteInterest(fd, enable, token.toUdata());
        s.target_write_registered = enable;
    }

    pub fn abortSession(self: *Socks5Service, s: *Session) void {
        if (!s.is_active) return;
        s.is_active = false;
        s.generation +%= 1;
        self.active_sessions_count -|= 1;

        // Clean wait queue
        var w_idx: usize = 0;
        while (w_idx < self.wait_queue.items.len) {
            if (self.wait_queue.items[w_idx].session_id == s.id) {
                _ = self.wait_queue.orderedRemove(w_idx);
            } else {
                w_idx += 1;
            }
        }

        // Release early payload if held by adapter
        if (s.adapter.early_payload) |buf| {
            self.pool.release(buf) catch {};
            s.adapter.early_payload = null;
            s.adapter.early_payload_len = 0;
        }

        // Unregister kqueue events
        const c_fd = if (s.client_fd >= 0) s.client_fd else s.adapter.client_fd;
        if (c_fd >= 0) {
            if (s.client_read_registered) self.reactor.unregister(c_fd, darwin.EVFILT_READ);
            if (s.client_write_registered) self.reactor.unregister(c_fd, darwin.EVFILT_WRITE);
        }

        const t_fd = if (s.target_fd >= 0) s.target_fd else s.adapter.target_fd;
        if (t_fd >= 0) {
            if (s.target_read_registered) self.reactor.unregister(t_fd, darwin.EVFILT_READ);
            if (s.target_write_registered) self.reactor.unregister(t_fd, darwin.EVFILT_WRITE);
        }

        // Abort adapter sockets
        s.adapter.abort();

        // Close relay sockets
        if (s.client_fd >= 0) {
            darwin.closeSocket(s.client_fd);
            s.client_fd = -1;
        }
        if (s.target_fd >= 0) {
            darwin.closeSocket(s.target_fd);
            s.target_fd = -1;
        }

        // Release lifecycle buffers to pool
        s.lifecycle.abort(&self.pool) catch {};

        s.client_read_registered = false;
        s.target_read_registered = false;
        s.client_write_registered = false;
        s.target_write_registered = false;
        s.client_waiting_pool = false;
        s.target_waiting_pool = false;
        s.deferred_target_shutdown_wr = false;
        s.phase = .idle;

        self.wakeWaitQueue();
    }

    fn acceptConnection(self: *Socks5Service, now_ms: i64) void {
        const acc = darwin.acceptNonBlocking(self.listener_fd) catch return;
        const res = switch (acc) {
            .Ok => |r| r,
            .WouldBlock, .Aborted => return,
        };

        var target_session: ?*Session = null;
        for (self.sessions) |*s| {
            if (!s.is_active) {
                target_session = s;
                break;
            }
        }

        const s = target_session orelse {
            darwin.closeSocket(res.fd);
            return;
        };

        s.is_active = true;
        s.phase = .handshake;
        s.client_fd = -1;
        s.target_fd = -1;
        s.adapter = .{
            .client_fd = res.fd,
            .target_fd = -1,
            .handshake = Socks5Handshake.init(),
            .handshake_deadline_ms = now_ms + self.config.handshake_timeout_ms,
        };
        s.client_read_registered = false;
        s.target_read_registered = false;
        s.client_write_registered = false;
        s.target_write_registered = false;
        s.client_waiting_pool = false;
        s.target_waiting_pool = false;
        s.deferred_target_shutdown_wr = false;
        s.lifecycle = TcpLifecycle.init(self.config.drain_timeout_ms);

        self.active_sessions_count += 1;

        self.updateClientReadInterest(s, true) catch {
            self.abortSession(s);
            return;
        };
    }

    fn startFlushingReply(self: *Socks5Service, s: *Session, target_phase: SessionPhase, now_ms: i64) void {
        s.phase = target_phase;
        s.adapter.reply_deadline_ms = now_ms + self.config.reply_timeout_ms;
        self.updateClientWriteInterest(s, true) catch {
            self.abortSession(s);
            return;
        };
    }

    fn flushReply(self: *Socks5Service, s: *Session, now_ms: i64) void {
        while (s.adapter.reply_offset < s.adapter.reply_len) {
            const remaining = s.adapter.reply_buf[s.adapter.reply_offset..s.adapter.reply_len];
            const wr = writeReplySocket(s.adapter.client_fd, remaining) catch {
                self.abortSession(s);
                return;
            };
            switch (wr) {
                .Ok => |w_bytes| {
                    if (w_bytes == 0) return;
                    s.adapter.reply_offset += w_bytes;
                },
                .WouldBlock => {
                    self.updateClientWriteInterest(s, true) catch {
                        self.abortSession(s);
                    };
                    return;
                },
                .BrokenPipe, .Reset => {
                    self.abortSession(s);
                    return;
                },
            }
        }

        // Reply completely sent
        self.updateClientWriteInterest(s, false) catch {};

        switch (s.phase) {
            .flushing_method_reply => {
                s.phase = .handshake;
                s.adapter.handshake_deadline_ms = now_ms + self.config.handshake_timeout_ms;
                if (s.adapter.pending_input_len > 0) {
                    var pending_buf: [1024]u8 = undefined;
                    const plen = s.adapter.pending_input_len;
                    @memcpy(pending_buf[0..plen], s.adapter.pending_input[0..plen]);
                    s.adapter.pending_input_len = 0;
                    self.processHandshakeBytes(s, pending_buf[0..plen], now_ms);
                }
                if (s.is_active and s.phase == .handshake and s.adapter.pending_input_len == 0) {
                    self.updateClientReadInterest(s, true) catch {
                        self.abortSession(s);
                        return;
                    };
                }
            },
            .flushing_connect_reply => {
                self.startRelay(s);
            },
            .flushing_error_reply => {
                self.abortSession(s);
            },
            else => {},
        }
    }

    fn processRequest(self: *Socks5Service, s: *Session, req: socks5.Socks5Request, now_ms: i64) void {
        if (req.command != .connect) {
            const rep = socks5.encodeDefaultReply(.command_not_supported);
            @memcpy(s.adapter.reply_buf[0..rep.len], &rep);
            s.adapter.reply_len = rep.len;
            s.adapter.reply_offset = 0;
            self.startFlushingReply(s, .flushing_error_reply, now_ms);
            self.flushReply(s, now_ms);
            return;
        }

        const action = self.router.route(req.endpoint);
        switch (action) {
            .block => {
                const rep = socks5.encodeDefaultReply(.connection_not_allowed);
                @memcpy(s.adapter.reply_buf[0..rep.len], &rep);
                s.adapter.reply_len = rep.len;
                s.adapter.reply_offset = 0;
                self.startFlushingReply(s, .flushing_error_reply, now_ms);
                self.flushReply(s, now_ms);
                return;
            },
            .direct => {
                switch (req.endpoint.address) {
                    .domain, .ipv6 => {
                        const rep = socks5.encodeDefaultReply(.address_type_not_supported);
                        @memcpy(s.adapter.reply_buf[0..rep.len], &rep);
                        s.adapter.reply_len = rep.len;
                        s.adapter.reply_offset = 0;
                        self.startFlushingReply(s, .flushing_error_reply, now_ms);
                        self.flushReply(s, now_ms);
                        return;
                    },
                    .ipv4 => |ip| {
                        const target_fd = darwin.createNonBlockingTcpSocket() catch {
                            const rep = socks5.encodeDefaultReply(.general_failure);
                            @memcpy(s.adapter.reply_buf[0..rep.len], &rep);
                            s.adapter.reply_len = rep.len;
                            s.adapter.reply_offset = 0;
                            self.startFlushingReply(s, .flushing_error_reply, now_ms);
                            self.flushReply(s, now_ms);
                            return;
                        };
                        s.adapter.target_fd = target_fd;

                        const dest_addr = darwin.sockaddr_in{
                            .port = std.mem.nativeToBig(u16, req.endpoint.port),
                            .addr = @bitCast(ip),
                        };

                        const conn_res = darwin.connectNonBlocking(target_fd, dest_addr) catch |err| {
                            darwin.closeSocket(target_fd);
                            s.adapter.target_fd = -1;
                            const rep_code = mapPlatformErrorToReplyCode(err);
                            const rep = socks5.encodeDefaultReply(rep_code);
                            @memcpy(s.adapter.reply_buf[0..rep.len], &rep);
                            s.adapter.reply_len = rep.len;
                            s.adapter.reply_offset = 0;
                            self.startFlushingReply(s, .flushing_error_reply, now_ms);
                            self.flushReply(s, now_ms);
                            return;
                        };

                        switch (conn_res) {
                            .Connected => {
                                self.onTargetConnected(s, now_ms);
                            },
                            .InProgress => {
                                s.phase = .connecting_target;
                                s.adapter.connect_deadline_ms = now_ms + self.config.connect_timeout_ms;
                                self.updateClientReadInterest(s, false) catch {};
                                self.updateTargetWriteInterest(s, true) catch {
                                    self.abortSession(s);
                                    return;
                                };
                            },
                        }
                    },
                }
            },
        }
    }

    fn onTargetConnected(self: *Socks5Service, s: *Session, now_ms: i64) void {
        const local_addr = darwin.getLocalAddress(s.adapter.target_fd) catch {
            const rep = socks5.encodeDefaultReply(.general_failure);
            @memcpy(s.adapter.reply_buf[0..rep.len], &rep);
            s.adapter.reply_len = rep.len;
            s.adapter.reply_offset = 0;
            self.startFlushingReply(s, .flushing_error_reply, now_ms);
            self.flushReply(s, now_ms);
            return;
        };

        const bnd_ip: [4]u8 = @bitCast(local_addr.addr);
        const bnd_port = std.mem.bigToNative(u16, local_addr.port);
        const bnd_ep = TargetEndpoint.initIpv4(bnd_ip, bnd_port);

        var buf: [64]u8 = undefined;
        const enc = socks5.encodeReply(&buf, .succeeded, bnd_ep) catch {
            self.abortSession(s);
            return;
        };

        @memcpy(s.adapter.reply_buf[0..enc.len], enc);
        s.adapter.reply_len = enc.len;
        s.adapter.reply_offset = 0;
        s.phase = .flushing_connect_reply;
        s.adapter.reply_deadline_ms = now_ms + self.config.reply_timeout_ms;

        self.flushReply(s, now_ms);
    }

    fn startRelay(self: *Socks5Service, s: *Session) void {
        const xfer = s.adapter.transferToRelay();
        s.client_fd = xfer.client_fd;
        s.target_fd = xfer.target_fd;
        s.phase = .relay;
        s.lifecycle = TcpLifecycle.init(self.config.drain_timeout_ms);

        if (s.adapter.early_payload) |early_buf| {
            _ = s.lifecycle.onDataRead(.client_to_target, early_buf, s.adapter.early_payload_len) catch {
                self.abortSession(s);
                return;
            };
            s.adapter.early_payload = null;
            s.adapter.early_payload_len = 0;

            self.updateTargetWriteInterest(s, true) catch {
                self.abortSession(s);
                return;
            };
        }

        self.updateClientReadInterest(s, true) catch {
            self.abortSession(s);
            return;
        };
        self.updateTargetReadInterest(s, true) catch {
            self.abortSession(s);
            return;
        };
    }

    fn processHandshakeBytes(self: *Socks5Service, s: *Session, input: []const u8, now_ms: i64) void {
        var used: usize = 0;
        while (used < input.len and s.is_active and s.phase == .handshake) {
            const feed_res = s.adapter.handshake.feed(input[used..]);
            switch (feed_res) {
                .need_more => break,
                .send_method_reply => |r| {
                    used += r.consumed;
                    if (r.method == .no_acceptable) {
                        s.adapter.reply_buf[0] = 0x05;
                        s.adapter.reply_buf[1] = 0xFF;
                        s.adapter.reply_len = 2;
                        s.adapter.reply_offset = 0;
                        self.startFlushingReply(s, .flushing_error_reply, now_ms);
                        self.flushReply(s, now_ms);
                        return;
                    } else {
                        s.adapter.reply_buf[0] = 0x05;
                        s.adapter.reply_buf[1] = 0x00;
                        s.adapter.reply_len = 2;
                        s.adapter.reply_offset = 0;
                        s.phase = .flushing_method_reply;
                        s.adapter.reply_deadline_ms = now_ms + self.config.reply_timeout_ms;

                        // Save any coalesced bytes for processing after method reply flush
                        if (used < input.len) {
                            const leftover = input[used..];
                            @memcpy(s.adapter.pending_input[0..leftover.len], leftover);
                            s.adapter.pending_input_len = leftover.len;
                            used = input.len;
                        }

                        self.flushReply(s, now_ms);
                        if (!s.is_active or s.phase != .handshake) {
                            if (s.is_active and s.phase == .flushing_method_reply) {
                                self.updateClientReadInterest(s, false) catch {};
                            }
                            return;
                        }
                    }
                },
                .request_done => |r| {
                    used += r.consumed;
                    if (used < input.len) {
                        const payload = input[used..];
                        const buf = self.pool.acquire() orelse {
                            self.abortSession(s);
                            return;
                        };
                        @memcpy(buf.memory[0..payload.len], payload);
                        s.adapter.early_payload = buf;
                        s.adapter.early_payload_len = payload.len;
                        used = input.len;
                    }
                    self.processRequest(s, r.request, now_ms);
                    return;
                },
                .err => {
                    if (s.adapter.handshake.getErrorReply()) |rep| {
                        @memcpy(s.adapter.reply_buf[0..rep.len], &rep);
                        s.adapter.reply_len = rep.len;
                        s.adapter.reply_offset = 0;
                        self.startFlushingReply(s, .flushing_error_reply, now_ms);
                        self.flushReply(s, now_ms);
                    } else {
                        self.abortSession(s);
                    }
                    return;
                },
            }
        }
    }

    fn handleClientHandshakeRead(self: *Socks5Service, s: *Session, flags: u16, now_ms: i64) void {
        var chunk: [1024]u8 = undefined;
        const read_res = darwin.readSocket(s.adapter.client_fd, &chunk) catch {
            self.abortSession(s);
            return;
        };

        switch (read_res) {
            .WouldBlock => return,
            .Eof => {
                _ = s.adapter.handshake.feedEof();
                if (s.adapter.handshake.getErrorReply()) |rep| {
                    @memcpy(s.adapter.reply_buf[0..rep.len], &rep);
                    s.adapter.reply_len = rep.len;
                    s.adapter.reply_offset = 0;
                    self.startFlushingReply(s, .flushing_error_reply, now_ms);
                    self.flushReply(s, now_ms);
                } else {
                    self.abortSession(s);
                }
            },
            .Reset => {
                self.abortSession(s);
            },
            .Ok => |n| {
                self.processHandshakeBytes(s, chunk[0..n], now_ms);
                if (flags & darwin.EV_EOF != 0 and s.is_active and s.phase == .handshake and s.adapter.pending_input_len == 0) {
                    _ = s.adapter.handshake.feedEof();
                    self.abortSession(s);
                }
            },
        }
    }

    fn handleConnectTimeout(self: *Socks5Service, s: *Session, now_ms: i64) void {
        if (s.adapter.target_fd >= 0) {
            darwin.closeSocket(s.adapter.target_fd);
            s.adapter.target_fd = -1;
        }
        const rep = socks5.encodeDefaultReply(.host_unreachable);
        @memcpy(s.adapter.reply_buf[0..rep.len], &rep);
        s.adapter.reply_len = rep.len;
        s.adapter.reply_offset = 0;
        self.startFlushingReply(s, .flushing_error_reply, now_ms);
        self.flushReply(s, now_ms);
    }

    fn handleTargetConnectWrite(self: *Socks5Service, s: *Session, now_ms: i64) void {
        if (s.adapter.connect_deadline_ms) |d| {
            if (now_ms >= d) {
                self.handleConnectTimeout(s, now_ms);
                return;
            }
        }

        const connected = darwin.checkSocketConnected(s.adapter.target_fd) catch |err| {
            darwin.closeSocket(s.adapter.target_fd);
            s.adapter.target_fd = -1;
            const rep_code = mapPlatformErrorToReplyCode(err);
            const rep = socks5.encodeDefaultReply(rep_code);
            @memcpy(s.adapter.reply_buf[0..rep.len], &rep);
            s.adapter.reply_len = rep.len;
            s.adapter.reply_offset = 0;
            self.startFlushingReply(s, .flushing_error_reply, now_ms);
            self.flushReply(s, now_ms);
            return;
        };

        if (!connected) {
            darwin.closeSocket(s.adapter.target_fd);
            s.adapter.target_fd = -1;
            const rep = socks5.encodeDefaultReply(.connection_refused);
            @memcpy(s.adapter.reply_buf[0..rep.len], &rep);
            s.adapter.reply_len = rep.len;
            s.adapter.reply_offset = 0;
            self.startFlushingReply(s, .flushing_error_reply, now_ms);
            self.flushReply(s, now_ms);
            return;
        }

        self.updateTargetWriteInterest(s, false) catch {};
        self.onTargetConnected(s, now_ms);
    }

    fn handleRelayRead(self: *Socks5Service, s: *Session, dir: Direction, event_flags: u16, now_ms: i64) void {
        const src_fd = if (dir == .client_to_target) s.client_fd else s.target_fd;

        if (!s.lifecycle.canReadSource(dir)) {
            if (dir == .client_to_target) {
                self.updateClientReadInterest(s, false) catch {};
            } else {
                self.updateTargetReadInterest(s, false) catch {};
            }
            return;
        }

        const buf = self.pool.acquire() orelse {
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

        const read_res = darwin.readSocket(src_fd, buf.memory[0..buffer_pool.BUFFER_SIZE]) catch {
            self.pool.release(buf) catch {};
            self.abortSession(s);
            return;
        };

        switch (read_res) {
            .WouldBlock => {
                self.pool.release(buf) catch {};
                if (event_flags & darwin.EV_EOF != 0) {
                    self.handleRelayEof(s, dir, now_ms);
                }
            },
            .Ok => |read_bytes| {
                const action = s.lifecycle.onDataRead(dir, buf, read_bytes) catch {
                    self.pool.release(buf) catch {};
                    self.abortSession(s);
                    return;
                };

                if (action.unregister_source_read) {
                    if (dir == .client_to_target) {
                        self.updateClientReadInterest(s, false) catch {
                            self.abortSession(s);
                            return;
                        };
                    } else {
                        self.updateTargetReadInterest(s, false) catch {
                            self.abortSession(s);
                            return;
                        };
                    }
                }

                if (action.register_dest_write) {
                    if (dir == .client_to_target) {
                        self.updateTargetWriteInterest(s, true) catch {
                            self.abortSession(s);
                            return;
                        };
                    } else {
                        self.updateClientWriteInterest(s, true) catch {
                            self.abortSession(s);
                            return;
                        };
                    }
                }

                // Do not invoke handleRelayEof here! EV_EOF may arrive while unread data
                // remains in the kernel socket buffer. Only WouldBlock with EV_EOF or Eof
                // signifies that the kernel receive buffer is completely drained.
            },
            .Eof => {
                self.pool.release(buf) catch {};
                self.handleRelayEof(s, dir, now_ms);
            },
            .Reset => {
                self.pool.release(buf) catch {};
                self.abortSession(s);
            },
        }
    }

    fn handleRelayWrite(self: *Socks5Service, s: *Session, dir: Direction) void {
        const dest_fd = if (dir == .client_to_target) s.target_fd else s.client_fd;
        const q_idx = @intFromEnum(dir);

        const slice = s.lifecycle.queues[q_idx].peek() orelse {
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
                        self.abortSession(s);
                        return;
                    }
                }
            },
            .WouldBlock => return,
            .BrokenPipe, .Reset => {
                self.abortSession(s);
            },
        }
    }

    fn wakeWaitQueue(self: *Socks5Service) void {
        if (self.in_wake) return;
        self.in_wake = true;
        defer self.in_wake = false;

        while (self.pool.available() > 0 and self.wait_queue.items.len > 0) {
            const entry = self.wait_queue.orderedRemove(0);
            if (entry.session_id >= self.sessions.len) continue;
            const s = &self.sessions[entry.session_id];
            if (!s.is_active or s.phase != .relay) continue;

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

    fn handleRelayEof(self: *Socks5Service, s: *Session, dir: Direction, now_ms: i64) void {
        const action = s.lifecycle.onSourceEof(dir, now_ms);
        switch (dir) {
            .client_to_target => {
                self.updateClientReadInterest(s, false) catch {};
                if (action.shutdown_dest_write) {
                    darwin.shutdownSocket(s.target_fd, darwin.SHUT_WR);
                    self.updateTargetWriteInterest(s, false) catch {};
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
            self.abortSession(s);
        }
    }

    fn checkDeadlines(self: *Socks5Service, now_ms: i64) void {
        for (self.sessions) |*s| {
            if (!s.is_active) continue;

            switch (s.phase) {
                .handshake => {
                    if (now_ms >= s.adapter.handshake_deadline_ms) {
                        self.abortSession(s);
                    }
                },
                .flushing_method_reply, .flushing_connect_reply, .flushing_error_reply => {
                    if (s.adapter.reply_deadline_ms) |d| {
                        if (now_ms >= d) {
                            self.abortSession(s);
                        }
                    }
                },
                .connecting_target => {
                    if (s.adapter.connect_deadline_ms) |d| {
                        if (now_ms >= d) {
                            self.handleConnectTimeout(s, now_ms);
                        }
                    }
                },
                .relay => {
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
                },
                .idle => {},
            }
        }
    }

    fn processEvent(self: *Socks5Service, ev: *const darwin.Kevent, now_ms: i64) bool {
        const token = EventToken.fromUdata(ev.udata);

        if (token.role == .listener) {
            self.acceptConnection(now_ms);
            return true;
        }

        if (token.session_id >= self.sessions.len) return false;
        const s = &self.sessions[token.session_id];
        if (!s.is_active or s.generation != token.generation) return false;

        // Double check deadline for this session in case it expired
        switch (s.phase) {
            .handshake => {
                if (now_ms >= s.adapter.handshake_deadline_ms) {
                    self.abortSession(s);
                    return false;
                }
            },
            .flushing_method_reply, .flushing_connect_reply, .flushing_error_reply => {
                if (s.adapter.reply_deadline_ms) |d| {
                    if (now_ms >= d) {
                        self.abortSession(s);
                        return false;
                    }
                }
            },
            .connecting_target => {
                if (s.adapter.connect_deadline_ms) |d| {
                    if (now_ms >= d) {
                        self.handleConnectTimeout(s, now_ms);
                        return false;
                    }
                }
            },
            .relay => {
                if (s.lifecycle.stream_state[0] == .draining) {
                    if (s.lifecycle.checkDrainDeadline(.client_to_target, now_ms, &self.pool) catch false) {
                        self.abortSession(s);
                        return false;
                    }
                }
                if (s.lifecycle.stream_state[1] == .draining) {
                    if (s.lifecycle.checkDrainDeadline(.target_to_client, now_ms, &self.pool) catch false) {
                        self.abortSession(s);
                        return false;
                    }
                }
            },
            .idle => return false,
        }

        switch (s.phase) {
            .handshake => {
                if (token.role == .client and ev.filter == darwin.EVFILT_READ) {
                    self.handleClientHandshakeRead(s, ev.flags, now_ms);
                    return true;
                }
            },
            .flushing_method_reply, .flushing_connect_reply, .flushing_error_reply => {
                if (token.role == .client and ev.filter == darwin.EVFILT_WRITE) {
                    self.flushReply(s, now_ms);
                    return true;
                }
            },
            .connecting_target => {
                if (token.role == .target and ev.filter == darwin.EVFILT_WRITE) {
                    self.handleTargetConnectWrite(s, now_ms);
                    return true;
                }
                if (token.role == .client and ev.filter == darwin.EVFILT_READ) {
                    if (ev.flags & darwin.EV_EOF != 0) {
                        self.abortSession(s);
                        return true;
                    }
                }
            },
            .relay => {
                if (ev.filter == darwin.EVFILT_READ) {
                    const dir: Direction = if (token.role == .client) .client_to_target else .target_to_client;
                    self.handleRelayRead(s, dir, ev.flags, now_ms);
                    return true;
                } else if (ev.filter == darwin.EVFILT_WRITE) {
                    const dir: Direction = if (token.role == .client) .target_to_client else .client_to_target;
                    self.handleRelayWrite(s, dir);
                    return true;
                }
            },
            .idle => return false,
        }

        return false;
    }

    /// Advances reactor event loop by one poll cycle.
    /// Caps poll timeout by nearest pending deadline across all active sessions.
    pub fn step(self: *Socks5Service, timeout_ms: ?i64) !usize {
        const pre_now_ms = darwin.getMonotonicMs();

        // 1. Enforce expired deadlines BEFORE polling
        self.checkDeadlines(pre_now_ms);

        var nearest_deadline_ms: ?i64 = null;
        for (self.sessions) |*s| {
            if (!s.is_active) continue;

            switch (s.phase) {
                .handshake => {
                    nearest_deadline_ms = minDeadline(nearest_deadline_ms, s.adapter.handshake_deadline_ms);
                },
                .flushing_method_reply, .flushing_connect_reply, .flushing_error_reply => {
                    if (s.adapter.reply_deadline_ms) |d| {
                        nearest_deadline_ms = minDeadline(nearest_deadline_ms, d);
                    }
                },
                .connecting_target => {
                    if (s.adapter.connect_deadline_ms) |d| {
                        nearest_deadline_ms = minDeadline(nearest_deadline_ms, d);
                    }
                },
                .relay => {
                    if (s.lifecycle.stream_state[0] == .draining) {
                        if (s.lifecycle.drain_deadline_ms[0]) |d| {
                            nearest_deadline_ms = minDeadline(nearest_deadline_ms, d);
                        }
                    }
                    if (s.lifecycle.stream_state[1] == .draining) {
                        if (s.lifecycle.drain_deadline_ms[1]) |d| {
                            nearest_deadline_ms = minDeadline(nearest_deadline_ms, d);
                        }
                    }
                },
                .idle => {},
            }
        }

        var effective_timeout_ms: ?i64 = timeout_ms;
        if (nearest_deadline_ms) |dead| {
            const time_to_dead = @max(@as(i64, 0), dead - pre_now_ms);
            effective_timeout_ms = if (effective_timeout_ms) |t| @min(t, time_to_dead) else time_to_dead;
        }

        var events: [64]darwin.Kevent = undefined;
        const count = try self.reactor.poll(&events, effective_timeout_ms);
        const post_now_ms = darwin.getMonotonicMs();

        // 2. Enforce expired deadlines BEFORE processing ready events!
        self.checkDeadlines(post_now_ms);

        for (events[0..count]) |*ev| {
            _ = self.processEvent(ev, post_now_ms);
        }

        // 3. Post-event check
        self.checkDeadlines(post_now_ms);

        return count;
    }
};

// ============================================================================
// Comprehensive Unit & Integration Tests (M1a.4)
// ============================================================================

const LoopbackSocks5Harness = struct {
    allocator: std.mem.Allocator,
    target_listener: darwin.fd_t,
    target_port: u16,
    socks5_listener: darwin.fd_t,
    socks5_port: u16,
    service: Socks5Service,

    pub fn init(
        allocator: std.mem.Allocator,
        router: Router,
        config: Socks5Config,
    ) !LoopbackSocks5Harness {
        const target_listener = try darwin.createNonBlockingTcpSocket();
        errdefer darwin.closeSocket(target_listener);
        try darwin.setReuseAddress(target_listener);
        const t_addr = darwin.makeLoopbackAddr(0);
        if (darwin.bind(target_listener, @ptrCast(&t_addr), @sizeOf(darwin.sockaddr_in)) < 0) return error.BindFailed;
        if (darwin.listen(target_listener, 16) < 0) return error.ListenFailed;
        const bound_target = try darwin.getLocalAddress(target_listener);
        const target_port = std.mem.bigToNative(u16, bound_target.port);

        const socks5_listener = try darwin.createNonBlockingTcpSocket();
        errdefer darwin.closeSocket(socks5_listener);
        try darwin.setReuseAddress(socks5_listener);
        const s_addr = darwin.makeLoopbackAddr(0);
        if (darwin.bind(socks5_listener, @ptrCast(&s_addr), @sizeOf(darwin.sockaddr_in)) < 0) return error.BindFailed;
        if (darwin.listen(socks5_listener, 16) < 0) return error.ListenFailed;
        const bound_socks5 = try darwin.getLocalAddress(socks5_listener);
        const socks5_port = std.mem.bigToNative(u16, bound_socks5.port);

        const service = try Socks5Service.init(allocator, socks5_listener, router, config);

        return .{
            .allocator = allocator,
            .target_listener = target_listener,
            .target_port = target_port,
            .socks5_listener = socks5_listener,
            .socks5_port = socks5_port,
            .service = service,
        };
    }

    pub fn deinit(self: *LoopbackSocks5Harness) void {
        self.service.deinit();
        darwin.closeSocket(self.socks5_listener);
        darwin.closeSocket(self.target_listener);
    }

    pub fn connectClient(self: *LoopbackSocks5Harness) !darwin.fd_t {
        const client_fd = try darwin.createNonBlockingTcpSocket();
        errdefer darwin.closeSocket(client_fd);
        const s_addr = darwin.makeLoopbackAddr(self.socks5_port);
        _ = try darwin.connectNonBlocking(client_fd, s_addr);
        return client_fd;
    }

    pub fn acceptTarget(self: *LoopbackSocks5Harness) !darwin.fd_t {
        var retries: usize = 0;
        while (retries < 100) : (retries += 1) {
            const acc = try darwin.acceptNonBlocking(self.target_listener);
            switch (acc) {
                .Ok => |r| return r.fd,
                .WouldBlock, .Aborted => darwin.sleepMs(2),
            }
        }
        return error.TargetAcceptTimeout;
    }

    pub fn stepLoop(self: *LoopbackSocks5Harness, times: usize) !void {
        for (0..times) |_| {
            _ = try self.service.step(5);
        }
    }
};

fn readExactBytes(fd: darwin.fd_t, buf: []u8) !void {
    var total: usize = 0;
    var retries: usize = 0;
    while (total < buf.len and retries < 200) : (retries += 1) {
        const res = darwin.readSocket(fd, buf[total..]) catch break;
        switch (res) {
            .Ok => |n| {
                total += n;
                retries = 0;
            },
            .WouldBlock => darwin.sleepMs(2),
            .Eof, .Reset => break,
        }
    }
    if (total != buf.len) return error.IncompleteRead;
}

test "socks5_service: Direct route bidirectional relay through loopback" {
    const router = Router.initStatic(&[_]router_mod.Rule{}, .direct);
    var harness = try LoopbackSocks5Harness.init(std.testing.allocator, router, .{});
    defer harness.deinit();

    const client_fd = try harness.connectClient();
    defer darwin.closeSocket(client_fd);

    try harness.stepLoop(3);

    // 1. Send greeting (No-Auth)
    _ = try darwin.writeSocket(client_fd, &[_]u8{ 5, 1, 0 });
    try harness.stepLoop(3);

    var method_rep: [2]u8 = undefined;
    try readExactBytes(client_fd, &method_rep);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 5, 0 }, &method_rep);

    // 2. Send CONNECT to target
    const req = [_]u8{
        5,                                           1,                                    0, 1,
        127,                                         0,                                    0, 1,
        @intCast((harness.target_port >> 8) & 0xFF), @intCast(harness.target_port & 0xFF),
    };
    _ = try darwin.writeSocket(client_fd, &req);
    try harness.stepLoop(5);

    const target_fd = try harness.acceptTarget();
    defer darwin.closeSocket(target_fd);

    try harness.stepLoop(5);

    // 3. Read connect reply
    var connect_rep: [10]u8 = undefined;
    try readExactBytes(client_fd, &connect_rep);
    try std.testing.expectEqual(@as(u8, 5), connect_rep[0]);
    try std.testing.expectEqual(@as(u8, 0), connect_rep[1]); // Succeeded!
    try std.testing.expectEqual(@as(u8, 0), connect_rep[2]);
    try std.testing.expectEqual(@as(u8, 1), connect_rep[3]); // IPv4 BND.ADDR

    // 4. Bidirectional relay
    const client_msg = "DIRECT_PING_DATA";
    _ = try darwin.writeSocket(client_fd, client_msg);
    try harness.stepLoop(5);

    var target_buf: [client_msg.len]u8 = undefined;
    try readExactBytes(target_fd, &target_buf);
    try std.testing.expectEqualStrings(client_msg, &target_buf);

    const target_reply = "DIRECT_PONG_REPLY";
    _ = try darwin.writeSocket(target_fd, target_reply);
    try harness.stepLoop(5);

    var client_recv: [target_reply.len]u8 = undefined;
    try readExactBytes(client_fd, &client_recv);
    try std.testing.expectEqualStrings(target_reply, &client_recv);
}

test "socks5_service: Block route returns connection_not_allowed and creates no target socket" {
    const rules = [_]router_mod.Rule{
        .{
            .action = .block,
            .ipv4_cidr = try router_mod.Ipv4Cidr.parse("127.0.0.1/32"),
        },
    };
    const router = Router.initStatic(&rules, .direct);
    var harness = try LoopbackSocks5Harness.init(std.testing.allocator, router, .{});
    defer harness.deinit();

    const client_fd = try harness.connectClient();
    defer darwin.closeSocket(client_fd);

    try harness.stepLoop(3);

    // 1. Send greeting
    _ = try darwin.writeSocket(client_fd, &[_]u8{ 5, 1, 0 });
    try harness.stepLoop(3);

    var method_rep: [2]u8 = undefined;
    try readExactBytes(client_fd, &method_rep);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 5, 0 }, &method_rep);

    // 2. Send CONNECT to blocked IP
    const req = [_]u8{
        5,                                           1,                                    0, 1,
        127,                                         0,                                    0, 1,
        @intCast((harness.target_port >> 8) & 0xFF), @intCast(harness.target_port & 0xFF),
    };
    _ = try darwin.writeSocket(client_fd, &req);
    try harness.stepLoop(5);

    // 3. Target listener receives NO connection
    const acc = try darwin.acceptNonBlocking(harness.target_listener);
    try std.testing.expectEqual(darwin.AcceptResult.WouldBlock, acc);

    // 4. Client receives connection_not_allowed (0x02)
    var connect_rep: [10]u8 = undefined;
    try readExactBytes(client_fd, &connect_rep);
    try std.testing.expectEqual(@as(u8, 5), connect_rep[0]);
    try std.testing.expectEqual(@as(u8, 2), connect_rep[1]); // connection_not_allowed

    // 5. Connection closes after block reply
    try harness.stepLoop(5);
    var eof_buf: [1]u8 = undefined;
    const r = try darwin.readSocket(client_fd, &eof_buf);
    try std.testing.expectEqual(darwin.ReadResult.Eof, r);
    try std.testing.expectEqual(@as(usize, 0), harness.service.active_sessions_count);
}

test "socks5_service: connect failure returns connection_refused without false success" {
    // Ephemeral port that is closed
    const tmp_sock = try darwin.createNonBlockingTcpSocket();
    const tmp_addr = darwin.makeLoopbackAddr(0);
    _ = darwin.bind(tmp_sock, @ptrCast(&tmp_addr), @sizeOf(darwin.sockaddr_in));
    const bound = try darwin.getLocalAddress(tmp_sock);
    const closed_port = std.mem.bigToNative(u16, bound.port);
    darwin.closeSocket(tmp_sock); // Closed immediately

    const router = Router.initStatic(&[_]router_mod.Rule{}, .direct);
    var harness = try LoopbackSocks5Harness.init(std.testing.allocator, router, .{});
    defer harness.deinit();

    const client_fd = try harness.connectClient();
    defer darwin.closeSocket(client_fd);

    try harness.stepLoop(3);

    // Greeting
    _ = try darwin.writeSocket(client_fd, &[_]u8{ 5, 1, 0 });
    try harness.stepLoop(3);

    var method_rep: [2]u8 = undefined;
    try readExactBytes(client_fd, &method_rep);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 5, 0 }, &method_rep);

    // CONNECT to closed port
    const req = [_]u8{
        5,                                   1,                            0, 1,
        127,                                 0,                            0, 1,
        @intCast((closed_port >> 8) & 0xFF), @intCast(closed_port & 0xFF),
    };
    _ = try darwin.writeSocket(client_fd, &req);
    try harness.stepLoop(10);

    // Client receives connection_refused (0x05)
    var rep: [10]u8 = undefined;
    try readExactBytes(client_fd, &rep);
    try std.testing.expectEqual(@as(u8, 5), rep[0]);
    try std.testing.expectEqual(@as(u8, 5), rep[1]); // connection_refused! NOT succeeded (0x00)!

    try harness.stepLoop(3);
    try std.testing.expectEqual(@as(usize, 0), harness.service.active_sessions_count);
}

test "socks5_service: coalesced handshake and early payload preserved without loss" {
    const router = Router.initStatic(&[_]router_mod.Rule{}, .direct);
    var harness = try LoopbackSocks5Harness.init(std.testing.allocator, router, .{});
    defer harness.deinit();

    const client_fd = try harness.connectClient();
    defer darwin.closeSocket(client_fd);

    try harness.stepLoop(3);

    // Send greeting + request + early payload in ONE chunk
    const early_payload = "EARLY_PAYLOAD_BYTES_COALESCED";
    var packet: [3 + 10 + early_payload.len]u8 = undefined;
    @memcpy(packet[0..3], &[_]u8{ 5, 1, 0 });
    const req = [_]u8{
        5,                                           1,                                    0, 1,
        127,                                         0,                                    0, 1,
        @intCast((harness.target_port >> 8) & 0xFF), @intCast(harness.target_port & 0xFF),
    };
    @memcpy(packet[3..13], &req);
    @memcpy(packet[13..], early_payload);

    _ = try darwin.writeSocket(client_fd, &packet);
    try harness.stepLoop(5);

    const target_fd = try harness.acceptTarget();
    defer darwin.closeSocket(target_fd);

    try harness.stepLoop(5);

    // Client reads method reply followed by connect reply
    var both_replies: [12]u8 = undefined;
    try readExactBytes(client_fd, &both_replies);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 5, 0 }, both_replies[0..2]);
    try std.testing.expectEqual(@as(u8, 5), both_replies[2]);
    try std.testing.expectEqual(@as(u8, 0), both_replies[3]); // Success

    // Target receives the early payload without loss!
    var target_payload: [early_payload.len]u8 = undefined;
    try readExactBytes(target_fd, &target_payload);
    try std.testing.expectEqualStrings(early_payload, &target_payload);
}

test "socks5_service: byte-by-byte fragmented handshake" {
    const router = Router.initStatic(&[_]router_mod.Rule{}, .direct);
    var harness = try LoopbackSocks5Harness.init(std.testing.allocator, router, .{});
    defer harness.deinit();

    const client_fd = try harness.connectClient();
    defer darwin.closeSocket(client_fd);

    try harness.stepLoop(3);

    // Send greeting byte-by-byte
    const greeting_bytes = [_]u8{ 5, 1, 0 };
    for (greeting_bytes) |b| {
        _ = try darwin.writeSocket(client_fd, &[_]u8{b});
        try harness.stepLoop(2);
    }

    var method_rep: [2]u8 = undefined;
    try readExactBytes(client_fd, &method_rep);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 5, 0 }, &method_rep);

    // Send request byte-by-byte
    const req_bytes = [_]u8{
        5,                                           1,                                    0, 1,
        127,                                         0,                                    0, 1,
        @intCast((harness.target_port >> 8) & 0xFF), @intCast(harness.target_port & 0xFF),
    };
    for (req_bytes) |b| {
        _ = try darwin.writeSocket(client_fd, &[_]u8{b});
        try harness.stepLoop(2);
    }

    const target_fd = try harness.acceptTarget();
    defer darwin.closeSocket(target_fd);

    try harness.stepLoop(5);

    var connect_rep: [10]u8 = undefined;
    try readExactBytes(client_fd, &connect_rep);
    try std.testing.expectEqual(@as(u8, 0), connect_rep[1]);
}

test "socks5_service: handshake timeout aborts inactive client" {
    const router = Router.initStatic(&[_]router_mod.Rule{}, .direct);
    var harness = try LoopbackSocks5Harness.init(std.testing.allocator, router, .{
        .handshake_timeout_ms = 30,
    });
    defer harness.deinit();

    const client_fd = try harness.connectClient();
    defer darwin.closeSocket(client_fd);

    try harness.stepLoop(2);

    // Send partial greeting
    _ = try darwin.writeSocket(client_fd, &[_]u8{5});

    // Wait past handshake timeout
    darwin.sleepMs(50);
    try harness.stepLoop(5);

    var eof_buf: [1]u8 = undefined;
    const r = try darwin.readSocket(client_fd, &eof_buf);
    try std.testing.expect(r == .Eof or r == .Reset);
    try std.testing.expectEqual(@as(usize, 0), harness.service.active_sessions_count);
}

test "socks5_service: half-close and drain" {
    const router = Router.initStatic(&[_]router_mod.Rule{}, .direct);
    var harness = try LoopbackSocks5Harness.init(std.testing.allocator, router, .{});
    defer harness.deinit();

    const client_fd = try harness.connectClient();
    defer darwin.closeSocket(client_fd);

    try harness.stepLoop(3);
    _ = try darwin.writeSocket(client_fd, &[_]u8{ 5, 1, 0 });
    try harness.stepLoop(3);

    var method_rep: [2]u8 = undefined;
    try readExactBytes(client_fd, &method_rep);

    const req = [_]u8{
        5,                                           1,                                    0, 1,
        127,                                         0,                                    0, 1,
        @intCast((harness.target_port >> 8) & 0xFF), @intCast(harness.target_port & 0xFF),
    };
    _ = try darwin.writeSocket(client_fd, &req);
    try harness.stepLoop(5);

    const target_fd = try harness.acceptTarget();
    defer darwin.closeSocket(target_fd);

    try harness.stepLoop(5);
    var connect_rep: [10]u8 = undefined;
    try readExactBytes(client_fd, &connect_rep);

    // Client sends half-close
    darwin.shutdownSocket(client_fd, darwin.SHUT_WR);
    try harness.stepLoop(5);

    // Target sees EOF on read
    var t_buf: [16]u8 = undefined;
    const t_read = try darwin.readSocket(target_fd, &t_buf);
    try std.testing.expectEqual(darwin.ReadResult.Eof, t_read);

    // Target sends final message before closing
    _ = try darwin.writeSocket(target_fd, "FINAL_WORDS");
    try harness.stepLoop(5);

    var final_buf: [11]u8 = undefined;
    try readExactBytes(client_fd, &final_buf);
    try std.testing.expectEqualStrings("FINAL_WORDS", &final_buf);
}

test "socks5_service: repeated connection cycles and resource cleanup" {
    const router = Router.initStatic(&[_]router_mod.Rule{}, .direct);
    var harness = try LoopbackSocks5Harness.init(std.testing.allocator, router, .{
        .max_sessions = 16,
    });
    defer harness.deinit();
    const fd_before = countOpenFds();

    for (0..10) |_| {
        const client_fd = try harness.connectClient();
        try harness.stepLoop(2);

        _ = try darwin.writeSocket(client_fd, &[_]u8{ 5, 1, 0 });
        try harness.stepLoop(2);

        var m_rep: [2]u8 = undefined;
        try readExactBytes(client_fd, &m_rep);

        const req = [_]u8{
            5,                                           1,                                    0, 1,
            127,                                         0,                                    0, 1,
            @intCast((harness.target_port >> 8) & 0xFF), @intCast(harness.target_port & 0xFF),
        };
        _ = try darwin.writeSocket(client_fd, &req);
        try harness.stepLoop(4);

        const target_fd = try harness.acceptTarget();
        try harness.stepLoop(4);

        var c_rep: [10]u8 = undefined;
        try readExactBytes(client_fd, &c_rep);

        darwin.closeSocket(client_fd);
        darwin.closeSocket(target_fd);
        try harness.stepLoop(4);
    }

    try std.testing.expectEqual(@as(usize, 0), harness.service.active_sessions_count);
    try std.testing.expectEqual(harness.service.pool.capacity, harness.service.pool.free_count);
    try std.testing.expectEqual(fd_before, countOpenFds());
}

fn countOpenFds() usize {
    var count: usize = 0;
    for (0..1024) |i| {
        if (darwin.fcntl(@as(darwin.fd_t, @intCast(i)), darwin.F_GETFD, @as(c_int, 0)) >= 0) {
            count += 1;
        }
    }
    return count;
}

fn reviewEstablished(h: *LoopbackSocks5Harness) !struct { client: darwin.fd_t, target: darwin.fd_t, session: *Session } {
    const client = try h.connectClient();
    errdefer darwin.closeSocket(client);
    try h.stepLoop(2);
    _ = try darwin.writeSocket(client, &.{ 5, 1, 0 });
    try h.stepLoop(2);
    var method: [2]u8 = undefined;
    try readExactBytes(client, &method);
    const req = [_]u8{ 5, 1, 0, 1, 127, 0, 0, 1, @intCast(h.target_port >> 8), @truncate(h.target_port) };
    _ = try darwin.writeSocket(client, &req);
    try h.stepLoop(3);
    const target = try h.acceptTarget();
    errdefer darwin.closeSocket(target);
    try h.stepLoop(2);
    var reply: [10]u8 = undefined;
    try readExactBytes(client, &reply);
    try std.testing.expectEqual(@as(u8, 0), reply[1]);
    for (h.service.sessions) |*session| {
        if (session.is_active and session.phase == .relay and session.lifecycle.queues[0].isEmpty()) {
            const peer = try darwin.getLocalAddress(client);
            var addr: darwin.sockaddr_in = undefined;
            var len: darwin.socklen_t = @sizeOf(darwin.sockaddr_in);
            if (std.c.getpeername(session.client_fd, @ptrCast(&addr), &len) == 0 and addr.port == peer.port) {
                return .{ .client = client, .target = target, .session = session };
            }
        }
    }
    return error.SessionNotFound;
}

fn reviewTail(direction: Direction) !void {
    var h = try LoopbackSocks5Harness.init(std.testing.allocator, Router.initStatic(&.{}, .direct), .{ .buffer_pool_capacity = 8 });
    defer h.deinit();
    const e = try reviewEstablished(&h);
    defer darwin.closeSocket(e.client);
    defer darwin.closeSocket(e.target);
    const src = if (direction == .client_to_target) e.client else e.target;
    const dest = if (direction == .client_to_target) e.target else e.client;
    const payload = [_]u8{'x'} ** (2 * buffer_pool.BUFFER_SIZE);
    var sent: usize = 0;
    while (sent < payload.len) {
        const wr = try darwin.writeSocket(src, payload[sent..]);
        switch (wr) {
            .Ok => |n| sent += n,
            .WouldBlock => darwin.sleepMs(1),
            else => return error.SendFailed,
        }
    }
    darwin.shutdownSocket(src, darwin.SHUT_WR);
    darwin.sleepMs(10);
    var received: usize = 0;
    var buf: [65536]u8 = undefined;
    for (0..30) |_| {
        _ = try h.service.step(1);
        const rr = try darwin.readSocket(dest, &buf);
        switch (rr) {
            .Ok => |n| received += n,
            .WouldBlock => {},
            .Eof, .Reset => break,
        }
    }
    try std.testing.expectEqual(sent, received);
}

test "review: client FIN preserves more than one relay buffer" {
    try reviewTail(.client_to_target);
}

test "review: target FIN preserves more than one relay buffer" {
    try reviewTail(.target_to_client);
}

test "review: final drain releases terminated session" {
    var h = try LoopbackSocks5Harness.init(std.testing.allocator, Router.initStatic(&.{}, .direct), .{ .buffer_pool_capacity = 2 });
    defer h.deinit();
    const e = try reviewEstablished(&h);
    defer darwin.closeSocket(e.client);
    defer darwin.closeSocket(e.target);
    for ([_]Direction{ .client_to_target, .target_to_client }) |dir| {
        const buf = h.service.pool.acquire().?;
        @memcpy(buf.memory[0..3], "abc");
        _ = try e.session.lifecycle.onDataRead(dir, buf, 3);
        if (dir == .client_to_target) {
            try h.service.updateTargetWriteInterest(e.session, true);
        } else {
            try h.service.updateClientWriteInterest(e.session, true);
        }
        h.service.handleRelayEof(e.session, dir, darwin.getMonotonicMs());
    }
    h.service.handleRelayWrite(e.session, .client_to_target);
    h.service.handleRelayWrite(e.session, .target_to_client);
    _ = try h.service.step(0);
    try std.testing.expect(!e.session.is_active);
    try std.testing.expectEqual(@as(usize, 0), h.service.active_sessions_count);
    try std.testing.expectEqual(@as(darwin.fd_t, -1), e.session.client_fd);
    try std.testing.expectEqual(@as(darwin.fd_t, -1), e.session.target_fd);
}

test "review: abort releasing pool wakes other session" {
    var h = try LoopbackSocks5Harness.init(std.testing.allocator, Router.initStatic(&.{}, .direct), .{ .buffer_pool_capacity = 1 });
    defer h.deinit();
    const a = try reviewEstablished(&h);
    defer darwin.closeSocket(a.client);
    defer darwin.closeSocket(a.target);
    const b = try reviewEstablished(&h);
    defer darwin.closeSocket(b.client);
    defer darwin.closeSocket(b.target);
    const held = h.service.pool.acquire().?;
    held.memory[0] = 'a';
    _ = try a.session.lifecycle.onDataRead(.client_to_target, held, 1);
    _ = try darwin.writeSocket(b.client, "b");
    h.service.handleRelayRead(b.session, .client_to_target, 0, darwin.getMonotonicMs());
    try std.testing.expect(b.session.client_waiting_pool);
    h.service.abortSession(a.session);
    try std.testing.expect(!b.session.client_waiting_pool);
    try std.testing.expect(b.session.client_read_registered);
}

test "review: coalesced request survives blocked method reply" {
    var h = try LoopbackSocks5Harness.init(std.testing.allocator, Router.initStatic(&.{}, .direct), .{});
    defer h.deinit();
    const client = try h.connectClient();
    defer darwin.closeSocket(client);
    try h.stepLoop(2);
    const s = &h.service.sessions[0];
    const packet = [_]u8{ 5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, @intCast(h.target_port >> 8), @truncate(h.target_port), 'p', 'a', 'y' };
    _ = try darwin.writeSocket(client, &packet);
    darwin.sleepMs(5);
    review_block_reply_write = true;
    defer review_block_reply_write = false;
    h.service.handleClientHandshakeRead(s, 0, darwin.getMonotonicMs());
    try std.testing.expectEqual(SessionPhase.flushing_method_reply, s.phase);
    review_block_reply_write = false;
    h.service.flushReply(s, darwin.getMonotonicMs());
    try h.stepLoop(3);
    try std.testing.expectEqual(SessionPhase.relay, s.phase);
    const target = try h.acceptTarget();
    defer darwin.closeSocket(target);
    var bytes: [3]u8 = undefined;
    try readExactBytes(target, &bytes);
    try std.testing.expectEqualStrings("pay", &bytes);
}

test "review: expired handshake cannot escape deadline through ready input" {
    var h = try LoopbackSocks5Harness.init(std.testing.allocator, Router.initStatic(&.{}, .direct), .{ .handshake_timeout_ms = 30 });
    defer h.deinit();
    const client = try h.connectClient();
    defer darwin.closeSocket(client);
    for (0..10) |_| {
        _ = try h.service.step(1);
        if (h.service.sessions[0].is_active) break;
    }
    const s = &h.service.sessions[0];
    try std.testing.expect(s.is_active);
    darwin.sleepMs(50);
    const request = [_]u8{ 5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, @intCast(h.target_port >> 8), @truncate(h.target_port) };
    _ = try darwin.writeSocket(client, &request);
    darwin.sleepMs(5);
    _ = try h.service.step(0);
    try std.testing.expect(!s.is_active);
}

test "review: expired reply cannot escape deadline through ready write" {
    var h = try LoopbackSocks5Harness.init(std.testing.allocator, Router.initStatic(&.{}, .direct), .{ .reply_timeout_ms = 30 });
    defer h.deinit();
    const client = try h.connectClient();
    defer darwin.closeSocket(client);
    try h.stepLoop(2);
    const s = &h.service.sessions[0];
    _ = try darwin.writeSocket(client, &.{ 5, 1, 0 });
    darwin.sleepMs(5);
    review_block_reply_write = true;
    defer review_block_reply_write = false;
    h.service.handleClientHandshakeRead(s, 0, darwin.getMonotonicMs());
    try std.testing.expectEqual(SessionPhase.flushing_method_reply, s.phase);
    darwin.sleepMs(50);
    review_block_reply_write = false;
    _ = try h.service.step(0);
    try std.testing.expect(!s.is_active);
}

test "review: service init allocation failures release memory and kqueue" {
    const listener = try darwin.createNonBlockingTcpSocket();
    defer darwin.closeSocket(listener);
    const addr = darwin.makeLoopbackAddr(0);
    if (darwin.bind(listener, @ptrCast(&addr), @sizeOf(darwin.sockaddr_in)) < 0) return error.BindFailed;
    if (darwin.listen(listener, 16) < 0) return error.ListenFailed;
    const before = countOpenFds();
    const serviceOOM = struct {
        fn run(allocator: std.mem.Allocator, l: darwin.fd_t) !void {
            var service = try Socks5Service.init(allocator, l, Router.initStatic(&.{}, .direct), .{
                .max_sessions = 2,
                .buffer_pool_capacity = 2,
            });
            defer service.deinit();
        }
    }.run;
    try std.testing.checkAllAllocationFailures(std.testing.allocator, serviceOOM, .{listener});
    try std.testing.expectEqual(before, countOpenFds());
}
