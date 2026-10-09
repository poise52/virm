const std = @import("std");

/// Darwin platform types and definitions from libSystem / POSIX.
pub const fd_t = std.c.fd_t;
pub const socklen_t = std.c.socklen_t;
pub const sockaddr = std.c.sockaddr;
pub const sockaddr_in = std.posix.sockaddr.in;
pub const timespec = std.c.timespec;
pub const Kevent = std.c.Kevent;

// Socket domains and types
pub const AF_INET: c_int = 2;
pub const SOCK_STREAM: c_int = 1;
pub const IPPROTO_TCP: c_int = 6;

// Socket options (Darwin specific constants)
pub const SOL_SOCKET: c_int = 0xffff;
pub const SO_REUSEADDR: c_int = 0x0004;
pub const SO_ERROR: c_int = 0x1007;
pub const SO_NOSIGPIPE: c_int = 0x1022;
pub const SO_SNDBUF: c_int = 0x1001;
pub const SO_RCVBUF: c_int = 0x1002;

// File control flags
pub const F_GETFL: c_int = 3;
pub const F_SETFL: c_int = 4;
pub const F_GETFD: c_int = 1;
pub const F_SETFD: c_int = 2;
pub const O_NONBLOCK: c_int = 0x0004;
pub const FD_CLOEXEC: c_int = 1;

// Shutdown directions
pub const SHUT_RD: c_int = 0;
pub const SHUT_WR: c_int = 1;
pub const SHUT_RDWR: c_int = 2;

// kqueue filter and event flags
pub const EVFILT_READ: i16 = std.c.EVFILT.READ;
pub const EVFILT_WRITE: i16 = std.c.EVFILT.WRITE;
pub const EV_ADD: u16 = std.c.EV.ADD;
pub const EV_DELETE: u16 = std.c.EV.DELETE;
pub const EV_ENABLE: u16 = std.c.EV.ENABLE;
pub const EV_DISABLE: u16 = std.c.EV.DISABLE;
pub const EV_CLEAR: u16 = std.c.EV.CLEAR;
pub const EV_EOF: u16 = std.c.EV.EOF;
pub const EV_ERROR: u16 = std.c.EV.ERROR;

// Direct C ABI bindings
pub const socket = std.c.socket;
pub const bind = std.c.bind;
pub const listen = std.c.listen;
pub const connect = std.c.connect;
pub const accept = std.c.accept;
pub const getsockopt = std.c.getsockopt;
pub const setsockopt = std.c.setsockopt;
pub const read = std.c.read;
pub const write = std.c.write;
pub const shutdown = std.c.shutdown;
pub const close = std.c.close;
pub const fcntl = std.c.fcntl;
pub const kqueue = std.c.kqueue;

pub extern "c" fn kevent(
    kq: c_int,
    changelist: ?[*]const Kevent,
    nchanges: c_int,
    eventlist: ?[*]Kevent,
    nevents: c_int,
    timeout: ?*const timespec,
) c_int;

pub fn getErrno() c_int {
    return std.c._errno().*;
}

pub const PlatformError = error{
    SocketCreationFailed,
    SetSockOptFailed,
    FcntlFailed,
    BindFailed,
    ListenFailed,
    ConnectionRefused,
    NetworkUnreachable,
    AddressInUse,
    ConnectionReset,
    TimedOut,
    Unexpected,
};

pub const AcceptResult = union(enum) {
    Ok: struct {
        fd: fd_t,
        addr: sockaddr_in,
    },
    WouldBlock: void,
    Aborted: void,
};

pub const ConnectResult = enum {
    Connected,
    InProgress,
};

pub const ReadResult = union(enum) {
    Ok: usize,
    Eof: void,
    WouldBlock: void,
    Reset: void,
};

pub const WriteResult = union(enum) {
    Ok: usize,
    WouldBlock: void,
    BrokenPipe: void,
    Reset: void,
};

/// Sets O_NONBLOCK on the given file descriptor using fcntl.
pub fn setNonBlocking(fd: fd_t) PlatformError!void {
    const flags = fcntl(fd, F_GETFL, @as(c_int, 0));
    if (flags < 0) return PlatformError.FcntlFailed;

    const rc = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (rc < 0) return PlatformError.FcntlFailed;
}

/// Sets FD_CLOEXEC on the given file descriptor using fcntl.
pub fn setCloseOnExec(fd: fd_t) PlatformError!void {
    const flags = fcntl(fd, F_GETFD, @as(c_int, 0));
    if (flags < 0) return PlatformError.FcntlFailed;

    const rc = fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    if (rc < 0) return PlatformError.FcntlFailed;
}

/// Suppresses SIGPIPE on socket writes on macOS via SO_NOSIGPIPE.
pub fn setNoSigPipe(fd: fd_t) PlatformError!void {
    const one: c_int = 1;
    const rc = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, @sizeOf(c_int));
    if (rc < 0) return PlatformError.SetSockOptFailed;
}

/// Sets SO_REUSEADDR on the socket to allow fast local rebinding.
pub fn setReuseAddress(fd: fd_t) PlatformError!void {
    const one: c_int = 1;
    const rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, @sizeOf(c_int));
    if (rc < 0) return PlatformError.SetSockOptFailed;
}

/// Creates a TCP socket pre-configured with O_NONBLOCK, FD_CLOEXEC, and SO_NOSIGPIPE.
pub fn createNonBlockingTcpSocket() PlatformError!fd_t {
    const raw_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (raw_fd < 0) return PlatformError.SocketCreationFailed;
    const fd: fd_t = @intCast(raw_fd);
    errdefer closeSocket(fd);

    try setNonBlocking(fd);
    try setCloseOnExec(fd);
    try setNoSigPipe(fd);

    return fd;
}

/// Accepts a connection on a nonblocking listening socket.
/// Automatically applies O_NONBLOCK, FD_CLOEXEC, and SO_NOSIGPIPE to the accepted socket.
pub fn acceptNonBlocking(listener_fd: fd_t) PlatformError!AcceptResult {
    var raw_addr: sockaddr_in = undefined;
    var addr_len: socklen_t = @sizeOf(sockaddr_in);

    const rc = accept(listener_fd, @ptrCast(&raw_addr), &addr_len);
    if (rc < 0) {
        const errno = getErrno();
        if (errno == @intFromEnum(std.posix.E.AGAIN)) {
            return .WouldBlock;
        }
        if (errno == @intFromEnum(std.posix.E.INTR)) {
            return .WouldBlock;
        }
        if (errno == @intFromEnum(std.posix.E.CONNABORTED)) {
            return .Aborted;
        }
        return PlatformError.Unexpected;
    }

    const client_fd: fd_t = @intCast(rc);
    errdefer closeSocket(client_fd);

    try setNonBlocking(client_fd);
    try setCloseOnExec(client_fd);
    try setNoSigPipe(client_fd);

    return .{
        .Ok = .{
            .fd = client_fd,
            .addr = raw_addr,
        },
    };
}

/// Initiates an asynchronous nonblocking TCP connection.
pub fn connectNonBlocking(fd: fd_t, addr: sockaddr_in) PlatformError!ConnectResult {
    const rc = connect(fd, @ptrCast(&addr), @sizeOf(sockaddr_in));
    if (rc == 0) return .Connected;

    const errno = getErrno();
    if (errno == @intFromEnum(std.posix.E.INPROGRESS) or
        errno == @intFromEnum(std.posix.E.AGAIN) or
        errno == @intFromEnum(std.posix.E.INTR))
    {
        return .InProgress;
    }

    return switch (errno) {
        @intFromEnum(std.posix.E.CONNREFUSED) => PlatformError.ConnectionRefused,
        @intFromEnum(std.posix.E.NETUNREACH) => PlatformError.NetworkUnreachable,
        @intFromEnum(std.posix.E.ADDRINUSE) => PlatformError.AddressInUse,
        @intFromEnum(std.posix.E.TIMEDOUT) => PlatformError.TimedOut,
        else => PlatformError.Unexpected,
    };
}

/// Queries SO_ERROR to check if an asynchronous connect succeeded.
pub fn checkSocketConnected(fd: fd_t) PlatformError!bool {
    var err: c_int = 0;
    var len: socklen_t = @sizeOf(c_int);
    const rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
    if (rc < 0) return PlatformError.Unexpected;

    if (err == 0) return true;

    return switch (err) {
        @intFromEnum(std.posix.E.CONNREFUSED) => PlatformError.ConnectionRefused,
        @intFromEnum(std.posix.E.NETUNREACH) => PlatformError.NetworkUnreachable,
        @intFromEnum(std.posix.E.TIMEDOUT) => PlatformError.TimedOut,
        @intFromEnum(std.posix.E.CONNRESET) => PlatformError.ConnectionReset,
        else => PlatformError.Unexpected,
    };
}

/// Performs a nonblocking read on the socket, handling EINTR and mapping errors.
pub fn readSocket(fd: fd_t, buf: []u8) PlatformError!ReadResult {
    while (true) {
        const rc = read(fd, buf.ptr, buf.len);
        if (rc > 0) {
            return .{ .Ok = @intCast(rc) };
        } else if (rc == 0) {
            return .Eof;
        } else {
            const errno = getErrno();
            if (errno == @intFromEnum(std.posix.E.INTR)) {
                continue;
            }
            if (errno == @intFromEnum(std.posix.E.AGAIN)) {
                return .WouldBlock;
            }
            if (errno == @intFromEnum(std.posix.E.CONNRESET) or
                errno == @intFromEnum(std.posix.E.PIPE))
            {
                return .Reset;
            }
            return PlatformError.Unexpected;
        }
    }
}

/// Performs a nonblocking write on the socket, handling EINTR and mapping errors.
pub fn writeSocket(fd: fd_t, data: []const u8) PlatformError!WriteResult {
    while (true) {
        const rc = write(fd, data.ptr, data.len);
        if (rc > 0) {
            return .{ .Ok = @intCast(rc) };
        } else if (rc == 0) {
            return .{ .Ok = 0 };
        } else {
            const errno = getErrno();
            if (errno == @intFromEnum(std.posix.E.INTR)) {
                continue;
            }
            if (errno == @intFromEnum(std.posix.E.AGAIN)) {
                return .WouldBlock;
            }
            if (errno == @intFromEnum(std.posix.E.PIPE)) {
                return .BrokenPipe;
            }
            if (errno == @intFromEnum(std.posix.E.CONNRESET)) {
                return .Reset;
            }
            return PlatformError.Unexpected;
        }
    }
}

/// Gracefully shuts down a direction of the socket (e.g. SHUT_WR for half-close).
pub fn shutdownSocket(fd: fd_t, how: c_int) void {
    _ = shutdown(fd, how);
}

/// Closes the socket file descriptor.
pub fn closeSocket(fd: fd_t) void {
    _ = close(fd);
}

/// Helper to create a loopback IPv4 sockaddr_in (127.0.0.1:port).
pub fn makeLoopbackAddr(port: u16) sockaddr_in {
    return .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7F000001), // 127.0.0.1 in network byte order
    };
}

/// Suspends execution for specified milliseconds using nanosleep.
pub fn sleepMs(ms: u32) void {
    const req = timespec{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * 1_000_000),
    };
    _ = std.c.nanosleep(&req, null);
}

/// Returns current monotonic timestamp in milliseconds.
pub fn getMonotonicMs() i64 {
    var ts: timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC_RAW, &ts);
    return (@as(i64, ts.sec) * 1000) + @divTrunc(ts.nsec, 1_000_000);
}

test "Darwin socket options and nonblocking loopback lifecycle" {
    const listener = try createNonBlockingTcpSocket();
    defer closeSocket(listener);
    try setReuseAddress(listener);

    const addr = makeLoopbackAddr(0); // Ephemeral port
    const bind_rc = bind(listener, @ptrCast(&addr), @sizeOf(sockaddr_in));
    try std.testing.expect(bind_rc == 0);

    const listen_rc = listen(listener, 16);
    try std.testing.expect(listen_rc == 0);

    // Get bound ephemeral port
    var bound_addr: sockaddr_in = undefined;
    var bound_len: socklen_t = @sizeOf(sockaddr_in);
    const gsn_rc = std.c.getsockname(listener, @ptrCast(&bound_addr), &bound_len);
    try std.testing.expect(gsn_rc == 0);
    const bound_port = std.mem.bigToNative(u16, bound_addr.port);

    // Empty accept returns WouldBlock
    const empty_acc = try acceptNonBlocking(listener);
    try std.testing.expectEqual(AcceptResult.WouldBlock, empty_acc);

    // Connect client
    const client = try createNonBlockingTcpSocket();
    defer closeSocket(client);

    const conn_res = try connectNonBlocking(client, makeLoopbackAddr(bound_port));
    // Either connected immediately or in progress
    _ = conn_res;

    // Accept client
    var accepted: ?fd_t = null;
    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        const acc_res = try acceptNonBlocking(listener);
        switch (acc_res) {
            .Ok => |info| {
                accepted = info.fd;
                break;
            },
            .WouldBlock => {
                sleepMs(1);
            },
            .Aborted => break,
        }
    }
    const server_fd = accepted orelse return error.TestUnexpectedResult;
    defer closeSocket(server_fd);

    // Verify client connection
    const is_conn = try checkSocketConnected(client);
    try std.testing.expect(is_conn);

    // Send payload client -> server
    const w_res = try writeSocket(client, "PING");
    try std.testing.expectEqual(@as(usize, 4), w_res.Ok);

    // Read payload on server
    var r_buf: [16]u8 = undefined;
    var r_ok = false;
    var r_attempts: usize = 0;
    while (r_attempts < 100) : (r_attempts += 1) {
        const r_res = try readSocket(server_fd, &r_buf);
        switch (r_res) {
            .Ok => |len| {
                try std.testing.expectEqualStrings("PING", r_buf[0..len]);
                r_ok = true;
                break;
            },
            .WouldBlock => {
                sleepMs(1);
            },
            else => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expect(r_ok);

    // Half-close write on client
    shutdownSocket(client, SHUT_WR);

    // Server reads EOF
    var eof_attempts: usize = 0;
    var got_eof = false;
    while (eof_attempts < 100) : (eof_attempts += 1) {
        const r_res = try readSocket(server_fd, &r_buf);
        switch (r_res) {
            .Eof => {
                got_eof = true;
                break;
            },
            .WouldBlock => {
                sleepMs(1);
            },
            else => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expect(got_eof);

    // But server can still send back to client!
    const w_back = try writeSocket(server_fd, "PONG");
    try std.testing.expectEqual(@as(usize, 4), w_back.Ok);

    var client_r_buf: [16]u8 = undefined;
    var got_pong = false;
    var pong_attempts: usize = 0;
    while (pong_attempts < 100) : (pong_attempts += 1) {
        const client_r_res = try readSocket(client, &client_r_buf);
        switch (client_r_res) {
            .Ok => |len| {
                try std.testing.expectEqual(@as(usize, 4), len);
                try std.testing.expectEqualStrings("PONG", client_r_buf[0..4]);
                got_pong = true;
                break;
            },
            .WouldBlock => {
                sleepMs(1);
            },
            else => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expect(got_pong);
}
