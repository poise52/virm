const std = @import("std");
const darwin = @import("../platform/darwin.zig");

pub const ReactorError = error{
    KqueueCreationFailed,
    KeventRegistrationFailed,
    PollFailed,
};

/// Encapsulates the Darwin kqueue event multiplexer.
pub const KqueueReactor = struct {
    kq_fd: darwin.fd_t,

    /// Initializes a new kqueue instance with FD_CLOEXEC.
    pub fn init() ReactorError!KqueueReactor {
        const raw_kq = darwin.kqueue();
        if (raw_kq < 0) {
            return ReactorError.KqueueCreationFailed;
        }
        const kq: darwin.fd_t = @intCast(raw_kq);
        errdefer darwin.closeSocket(kq);

        darwin.setCloseOnExec(kq) catch {
            return ReactorError.KqueueCreationFailed;
        };

        return .{ .kq_fd = kq };
    }

    /// Closes the kqueue file descriptor.
    pub fn deinit(self: *KqueueReactor) void {
        darwin.closeSocket(self.kq_fd);
        self.kq_fd = -1;
    }

    /// Registers or modifies an event filter on `fd` with the specified `flags` and `udata` token.
    pub fn register(
        self: *KqueueReactor,
        fd: darwin.fd_t,
        filter: i16,
        flags: u16,
        udata: usize,
    ) ReactorError!void {
        var change = darwin.Kevent{
            .ident = @intCast(fd),
            .filter = filter,
            .flags = flags,
            .fflags = 0,
            .data = 0,
            .udata = udata,
        };

        while (true) {
            const rc = darwin.kevent(self.kq_fd, @ptrCast(&change), 1, null, 0, null);
            if (rc >= 0) return;
            const errno = darwin.getErrno();
            if (errno == @intFromEnum(std.posix.E.INTR)) continue;
            return ReactorError.KeventRegistrationFailed;
        }
    }

    /// Convenience helper to register/enable or disable `EVFILT_READ`.
    pub fn setReadInterest(self: *KqueueReactor, fd: darwin.fd_t, enable: bool, udata: usize) ReactorError!void {
        if (enable) {
            try self.register(fd, darwin.EVFILT_READ, darwin.EV_ADD | darwin.EV_ENABLE, udata);
        } else {
            self.unregister(fd, darwin.EVFILT_READ);
        }
    }

    /// Convenience helper to register/enable or disable `EVFILT_WRITE`.
    pub fn setWriteInterest(self: *KqueueReactor, fd: darwin.fd_t, enable: bool, udata: usize) ReactorError!void {
        if (enable) {
            try self.register(fd, darwin.EVFILT_WRITE, darwin.EV_ADD | darwin.EV_ENABLE, udata);
        } else {
            self.unregister(fd, darwin.EVFILT_WRITE);
        }
    }

    /// Removes an event filter for `fd` from the kqueue.
    /// Safely ignores errors (e.g. ENOENT / EBADF if the socket was already closed).
    pub fn unregister(self: *KqueueReactor, fd: darwin.fd_t, filter: i16) void {
        var change = darwin.Kevent{
            .ident = @intCast(fd),
            .filter = filter,
            .flags = darwin.EV_DELETE,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        };
        while (true) {
            const rc = darwin.kevent(self.kq_fd, @ptrCast(&change), 1, null, 0, null);
            if (rc >= 0) return;
            const errno = darwin.getErrno();
            if (errno == @intFromEnum(std.posix.E.INTR)) continue;
            return;
        }
    }

    /// Waits for active events.
    /// `timeout_ms == null`: blocks indefinitely.
    /// `timeout_ms == 0`: non-blocking poll.
    /// `timeout_ms > 0`: blocks for at most `timeout_ms` milliseconds.
    pub fn poll(
        self: *KqueueReactor,
        event_buffer: []darwin.Kevent,
        timeout_ms: ?i64,
    ) ReactorError!usize {
        var ts_storage: darwin.timespec = undefined;
        const ts_ptr: ?*const darwin.timespec = if (timeout_ms) |t_ms| blk: {
            if (t_ms <= 0) {
                ts_storage = .{ .sec = 0, .nsec = 0 };
            } else {
                ts_storage = .{
                    .sec = @intCast(@divTrunc(t_ms, 1000)),
                    .nsec = @intCast(@mod(t_ms, 1000) * 1_000_000),
                };
            }
            break :blk &ts_storage;
        } else null;

        while (true) {
            const rc = darwin.kevent(
                self.kq_fd,
                null,
                0,
                event_buffer.ptr,
                @intCast(event_buffer.len),
                ts_ptr,
            );

            if (rc >= 0) {
                return @intCast(rc);
            }

            const errno = darwin.getErrno();
            if (errno == @intFromEnum(std.posix.E.INTR)) {
                return 0;
            }

            return ReactorError.PollFailed;
        }
    }
};

test "KqueueReactor basic register, poll, and unregister" {
    var reactor = try KqueueReactor.init();
    defer reactor.deinit();

    const listener = try darwin.createNonBlockingTcpSocket();
    defer darwin.closeSocket(listener);
    try darwin.setReuseAddress(listener);

    const addr = darwin.makeLoopbackAddr(0);
    _ = darwin.bind(listener, @ptrCast(&addr), @sizeOf(darwin.sockaddr_in));
    _ = darwin.listen(listener, 8);

    var bound_addr: darwin.sockaddr_in = undefined;
    var bound_len: darwin.socklen_t = @sizeOf(darwin.sockaddr_in);
    _ = std.c.getsockname(listener, @ptrCast(&bound_addr), &bound_len);
    const bound_port = std.mem.bigToNative(u16, bound_addr.port);

    const test_udata: usize = 0xDEADBEEF;
    try reactor.setReadInterest(listener, true, test_udata);

    var events: [8]darwin.Kevent = undefined;
    // Non-blocking poll: no connections yet -> 0 events
    const count0 = try reactor.poll(&events, 0);
    try std.testing.expectEqual(@as(usize, 0), count0);

    // Connect client to trigger listener readable event
    const client = try darwin.createNonBlockingTcpSocket();
    defer darwin.closeSocket(client);
    _ = try darwin.connectNonBlocking(client, darwin.makeLoopbackAddr(bound_port));

    // Poll with 100ms timeout
    const count1 = try reactor.poll(&events, 100);
    try std.testing.expect(count1 >= 1);
    try std.testing.expectEqual(@as(usize, @intCast(listener)), events[0].ident);
    try std.testing.expectEqual(darwin.EVFILT_READ, events[0].filter);
    try std.testing.expectEqual(test_udata, events[0].udata);

    // Unregister listener
    reactor.setReadInterest(listener, false, 0) catch {};

    const acc_res = try darwin.acceptNonBlocking(listener);
    const server_client = acc_res.Ok.fd;
    defer darwin.closeSocket(server_client);

    // No further events on listener
    const count2 = try reactor.poll(&events, 0);
    try std.testing.expectEqual(@as(usize, 0), count2);
}
