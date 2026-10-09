//! SOCKS5 Protocol Parser, Serializer, and Handshake FSM (RFC 1928)
//!
//! Provides incremental, bounded-memory parsing of SOCKS5 authentication
//! negotiation and CONNECT requests, typed results, RFC 1928 reply encoding,
//! and leftover payload preservation for TCP proxy relays.

const std = @import("std");

/// SOCKS protocol version 5.
pub const SOCKS5_VERSION: u8 = 0x05;

/// Maximum allowable domain name length in RFC 1928 (1-byte length prefix).
pub const MAX_DOMAIN_LEN: usize = 255;

/// Maximum methods count in greeting (1-byte prefix).
pub const MAX_METHODS: usize = 255;

/// Maximum possible size of SOCKS5 greeting: 1 (ver) + 1 (nmethods) + 255 (methods) = 257 bytes.
pub const MAX_GREETING_LEN: usize = 2 + MAX_METHODS;

/// Maximum possible size of SOCKS5 request: 1 (ver) + 1 (cmd) + 1 (rsv) + 1 (atyp) + 1 (dlen) + 255 (domain) + 2 (port) = 262 bytes.
pub const MAX_REQUEST_LEN: usize = 4 + 1 + MAX_DOMAIN_LEN + 2;

/// Internal header accumulation buffer size. Bounded and avoids heap allocation.
pub const HANDSHAKE_BUFFER_SIZE: usize = 512;

/// Authentication methods defined in RFC 1928.
pub const AuthMethod = enum(u8) {
    no_auth = 0x00,
    gssapi = 0x01,
    user_pass = 0x02,
    no_acceptable = 0xFF,
    _,
};

/// SOCKS5 commands defined in RFC 1928 Section 4.
pub const Command = enum(u8) {
    connect = 0x01,
    bind = 0x02,
    udp_associate = 0x03,
    _,
};

/// SOCKS5 address types defined in RFC 1928 Section 5.
pub const AddressType = enum(u8) {
    ipv4 = 0x01,
    domain = 0x03,
    ipv6 = 0x04,
    _,
};

/// SOCKS5 reply codes defined in RFC 1928 Section 6.
pub const ReplyCode = enum(u8) {
    succeeded = 0x00,
    general_failure = 0x01,
    connection_not_allowed = 0x02,
    network_unreachable = 0x03,
    host_unreachable = 0x04,
    connection_refused = 0x05,
    ttl_expired = 0x06,
    command_not_supported = 0x07,
    address_type_not_supported = 0x08,
    _,
};

/// Typed error reasons encountered during SOCKS5 parsing.
pub const HandshakeError = enum {
    unsupported_version,
    no_acceptable_methods,
    unsupported_command,
    unsupported_address_type,
    malformed_reserved,
    malformed_domain,
    empty_methods,
    buffer_overflow,
    unexpected_eof,
    invalid_state,
};

/// Strongly-typed destination address representation without heap allocation.
pub const TargetAddress = union(enum) {
    ipv4: [4]u8,
    domain: DomainName,
    ipv6: [16]u8,

    pub const DomainName = struct {
        buf: [MAX_DOMAIN_LEN]u8 = undefined,
        len: u8 = 0,

        pub fn init(name: []const u8) !DomainName {
            if (name.len == 0 or name.len > MAX_DOMAIN_LEN) return error.InvalidLength;
            var dn: DomainName = .{ .len = @intCast(name.len) };
            @memcpy(dn.buf[0..name.len], name);
            return dn;
        }

        pub fn slice(self: *const DomainName) []const u8 {
            return self.buf[0..self.len];
        }

        pub fn eql(self: *const DomainName, other: []const u8) bool {
            return std.mem.eql(u8, self.slice(), other);
        }
    };

    pub fn addressType(self: TargetAddress) AddressType {
        return switch (self) {
            .ipv4 => .ipv4,
            .domain => .domain,
            .ipv6 => .ipv6,
        };
    }

    pub fn format(
        self: TargetAddress,
        writer: *std.Io.Writer,
    ) !void {
        switch (self) {
            .ipv4 => |ip| try writer.print("{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }),
            .domain => |d| try writer.print("{s}", .{d.slice()}),
            .ipv6 => |ip| {
                var i: usize = 0;
                while (i < 16) : (i += 2) {
                    if (i > 0) try writer.writeAll(":");
                    const word = (@as(u16, ip[i]) << 8) | ip[i + 1];
                    try writer.print("{x}", .{word});
                }
            },
        }
    }
};

/// Combined destination target address and port endpoint.
pub const TargetEndpoint = struct {
    address: TargetAddress,
    port: u16,

    pub fn initIpv4(ip: [4]u8, port: u16) TargetEndpoint {
        return .{ .address = .{ .ipv4 = ip }, .port = port };
    }

    pub fn initIpv6(ip: [16]u8, port: u16) TargetEndpoint {
        return .{ .address = .{ .ipv6 = ip }, .port = port };
    }

    pub fn initDomain(name: []const u8, port: u16) !TargetEndpoint {
        return .{
            .address = .{ .domain = try TargetAddress.DomainName.init(name) },
            .port = port,
        };
    }

    pub fn format(
        self: TargetEndpoint,
        writer: *std.Io.Writer,
    ) !void {
        switch (self.address) {
            .ipv6 => try writer.print("[{f}]:{d}", .{ self.address, self.port }),
            else => try writer.print("{f}:{d}", .{ self.address, self.port }),
        }
    }
};

/// Parsed SOCKS5 client request.
pub const Socks5Request = struct {
    command: Command,
    endpoint: TargetEndpoint,
};

/// Result of stateless greeting parsing.
pub const GreetingParseResult = union(enum) {
    need_more: usize,
    done: struct {
        selected_method: AuthMethod,
        methods_count: u8,
        consumed: usize,
    },
    err: struct {
        code: HandshakeError,
        consumed: usize,
    },
};

/// Calculates exact required length for greeting header, or null if more bytes are needed.
pub fn expectedGreetingLen(slice: []const u8) ?usize {
    if (slice.len < 1) return null;
    if (slice[0] != SOCKS5_VERSION) return 1;
    if (slice.len < 2) return null;
    if (slice[1] == 0) return 2;
    return 2 + @as(usize, slice[1]);
}

/// Statelessly parses SOCKS5 greeting from `data`.
pub fn parseGreeting(data: []const u8) GreetingParseResult {
    if (data.len < 1) return .{ .need_more = 1 };
    if (data[0] != SOCKS5_VERSION) {
        return .{ .err = .{ .code = .unsupported_version, .consumed = 1 } };
    }
    if (data.len < 2) return .{ .need_more = 1 };
    const nmethods = data[1];
    if (nmethods == 0) {
        return .{ .err = .{ .code = .empty_methods, .consumed = 2 } };
    }
    const required_len = 2 + @as(usize, nmethods);
    if (data.len < required_len) {
        return .{ .need_more = required_len - data.len };
    }

    const methods = data[2..required_len];
    var has_no_auth = false;
    for (methods) |m| {
        if (m == @intFromEnum(AuthMethod.no_auth)) {
            has_no_auth = true;
            break;
        }
    }

    return .{
        .done = .{
            .selected_method = if (has_no_auth) .no_auth else .no_acceptable,
            .methods_count = nmethods,
            .consumed = required_len,
        },
    };
}

/// Result of stateless request parsing.
pub const RequestParseResult = union(enum) {
    need_more: usize,
    done: struct {
        request: Socks5Request,
        consumed: usize,
    },
    err: struct {
        code: HandshakeError,
        reply_code: ReplyCode,
        consumed: usize,
    },
};

/// Calculates exact required length for request header, or null if more bytes are needed.
pub fn expectedRequestLen(slice: []const u8) ?usize {
    if (slice.len < 1) return null;
    if (slice[0] != SOCKS5_VERSION) return 1;
    if (slice.len < 2) return null;
    if (slice[1] != @intFromEnum(Command.connect)) return 2;
    if (slice.len < 3) return null;
    if (slice[2] != 0x00) return 3;
    if (slice.len < 4) return null;

    const atyp = slice[3];
    switch (atyp) {
        @intFromEnum(AddressType.ipv4) => return 4 + 4 + 2,
        @intFromEnum(AddressType.ipv6) => return 4 + 16 + 2,
        @intFromEnum(AddressType.domain) => {
            if (slice.len < 5) return null;
            const dlen = slice[4];
            if (dlen == 0) return 5;
            return 5 + @as(usize, dlen) + 2;
        },
        else => return 4,
    }
}

/// Statelessly parses SOCKS5 request from `data`.
pub fn parseRequest(data: []const u8) RequestParseResult {
    if (data.len < 1) return .{ .need_more = 1 };
    if (data[0] != SOCKS5_VERSION) {
        return .{ .err = .{ .code = .unsupported_version, .reply_code = .general_failure, .consumed = 1 } };
    }
    if (data.len < 2) return .{ .need_more = 1 };
    const raw_cmd = data[1];
    if (raw_cmd != @intFromEnum(Command.connect)) {
        return .{ .err = .{ .code = .unsupported_command, .reply_code = .command_not_supported, .consumed = 2 } };
    }
    if (data.len < 3) return .{ .need_more = 1 };
    if (data[2] != 0x00) {
        return .{ .err = .{ .code = .malformed_reserved, .reply_code = .general_failure, .consumed = 3 } };
    }
    if (data.len < 4) return .{ .need_more = 1 };

    const raw_atyp = data[3];
    switch (raw_atyp) {
        @intFromEnum(AddressType.ipv4) => {
            const required_len = 4 + 4 + 2;
            if (data.len < required_len) return .{ .need_more = required_len - data.len };
            var ip: [4]u8 = undefined;
            @memcpy(&ip, data[4..8]);
            const port = std.mem.readInt(u16, data[8..10][0..2], .big);
            return .{
                .done = .{
                    .request = .{
                        .command = .connect,
                        .endpoint = TargetEndpoint.initIpv4(ip, port),
                    },
                    .consumed = required_len,
                },
            };
        },
        @intFromEnum(AddressType.ipv6) => {
            const required_len = 4 + 16 + 2;
            if (data.len < required_len) return .{ .need_more = required_len - data.len };
            var ip: [16]u8 = undefined;
            @memcpy(&ip, data[4..20]);
            const port = std.mem.readInt(u16, data[20..22][0..2], .big);
            return .{
                .done = .{
                    .request = .{
                        .command = .connect,
                        .endpoint = TargetEndpoint.initIpv6(ip, port),
                    },
                    .consumed = required_len,
                },
            };
        },
        @intFromEnum(AddressType.domain) => {
            if (data.len < 5) return .{ .need_more = 5 - data.len };
            const dlen = data[4];
            if (dlen == 0) {
                return .{ .err = .{ .code = .malformed_domain, .reply_code = .general_failure, .consumed = 5 } };
            }
            const dlen_usize: usize = dlen;
            const required_len = 5 + dlen_usize + 2;
            if (data.len < required_len) return .{ .need_more = required_len - data.len };
            const domain_slice = data[5 .. 5 + dlen_usize];
            var dn: TargetAddress.DomainName = .{ .len = dlen };
            @memcpy(dn.buf[0..dlen], domain_slice);
            const port_offset = 5 + dlen_usize;
            const port = std.mem.readInt(u16, data[port_offset .. port_offset + 2][0..2], .big);
            return .{
                .done = .{
                    .request = .{
                        .command = .connect,
                        .endpoint = .{
                            .address = .{ .domain = dn },
                            .port = port,
                        },
                    },
                    .consumed = required_len,
                },
            };
        },
        else => {
            return .{ .err = .{ .code = .unsupported_address_type, .reply_code = .address_type_not_supported, .consumed = 4 } };
        },
    }
}

/// Encodes method selection response (RFC 1928 Section 3).
pub fn encodeMethodSelection(method: AuthMethod) [2]u8 {
    return .{ SOCKS5_VERSION, @intFromEnum(method) };
}

/// Encodes default 10-byte SOCKS5 reply with 0.0.0.0:0 bound address.
pub fn encodeDefaultReply(reply_code: ReplyCode) [10]u8 {
    return .{
        SOCKS5_VERSION,
        @intFromEnum(reply_code),
        0x00, // RSV
        @intFromEnum(AddressType.ipv4),
        0x00,
        0x00,
        0x00,
        0x00, // 0.0.0.0
        0x00,
        0x00, // Port 0
    };
}

/// Encodes complete SOCKS5 reply with explicit bound endpoint (RFC 1928 Section 6).
pub fn encodeReply(buf: []u8, reply_code: ReplyCode, bnd: ?TargetEndpoint) ![]const u8 {
    const endpoint = bnd orelse TargetEndpoint.initIpv4([_]u8{ 0, 0, 0, 0 }, 0);
    switch (endpoint.address) {
        .ipv4 => |ip| {
            if (buf.len < 10) return error.BufferTooSmall;
            buf[0] = SOCKS5_VERSION;
            buf[1] = @intFromEnum(reply_code);
            buf[2] = 0x00;
            buf[3] = @intFromEnum(AddressType.ipv4);
            @memcpy(buf[4..8], &ip);
            std.mem.writeInt(u16, buf[8..10][0..2], endpoint.port, .big);
            return buf[0..10];
        },
        .ipv6 => |ip| {
            if (buf.len < 22) return error.BufferTooSmall;
            buf[0] = SOCKS5_VERSION;
            buf[1] = @intFromEnum(reply_code);
            buf[2] = 0x00;
            buf[3] = @intFromEnum(AddressType.ipv6);
            @memcpy(buf[4..20], &ip);
            std.mem.writeInt(u16, buf[20..22][0..2], endpoint.port, .big);
            return buf[0..22];
        },
        .domain => |d| {
            const needed = 4 + 1 + @as(usize, d.len) + 2;
            if (buf.len < needed) return error.BufferTooSmall;
            buf[0] = SOCKS5_VERSION;
            buf[1] = @intFromEnum(reply_code);
            buf[2] = 0x00;
            buf[3] = @intFromEnum(AddressType.domain);
            const dlen_usize: usize = d.len;
            buf[4] = d.len;
            @memcpy(buf[5 .. 5 + dlen_usize], d.slice());
            const p_offset = 5 + dlen_usize;
            std.mem.writeInt(u16, buf[p_offset .. p_offset + 2][0..2], endpoint.port, .big);
            return buf[0..needed];
        },
    }
}

/// State of the SOCKS5 handshake state machine.
pub const HandshakeState = enum {
    awaiting_greeting,
    awaiting_request,
    request_done,
    streaming,
    failed,
};

/// Result of feeding data to the state machine.
pub const FeedResult = union(enum) {
    need_more,
    send_method_reply: struct {
        method: AuthMethod,
        reply: [2]u8,
        consumed: usize,
    },
    request_done: struct {
        request: Socks5Request,
        consumed: usize,
    },
    err: struct {
        code: HandshakeError,
        reply_code: ?ReplyCode,
        consumed: usize,
    },
};

pub const HandshakeErrorInfo = struct {
    code: HandshakeError,
    reply_code: ?ReplyCode,
};

/// Incremental, zero-allocation SOCKS5 handshake state machine.
pub const Socks5Handshake = struct {
    state: HandshakeState = .awaiting_greeting,
    buf: [HANDSHAKE_BUFFER_SIZE]u8 = undefined,
    buf_len: usize = 0,
    selected_method: ?AuthMethod = null,
    request: ?Socks5Request = null,
    err_info: ?HandshakeErrorInfo = null,

    pub fn init() Socks5Handshake {
        return .{};
    }

    pub fn reset(self: *Socks5Handshake) void {
        self.* = init();
    }

    pub fn isDone(self: *const Socks5Handshake) bool {
        return self.state == .request_done or self.state == .streaming;
    }

    pub fn isFailed(self: *const Socks5Handshake) bool {
        return self.state == .failed;
    }

    pub fn markStreaming(self: *Socks5Handshake) void {
        if (self.state == .request_done) {
            self.state = .streaming;
        }
    }

    pub fn getMethodReply(self: *const Socks5Handshake) ?[2]u8 {
        if (self.selected_method) |m| {
            return encodeMethodSelection(m);
        }
        return null;
    }

    pub fn getErrorReply(self: *const Socks5Handshake) ?[10]u8 {
        if (self.err_info) |info| {
            if (info.reply_code) |rep| {
                return encodeDefaultReply(rep);
            }
        }
        return null;
    }

    /// Handles end-of-stream / connection close during handshake.
    pub fn feedEof(self: *Socks5Handshake) FeedResult {
        if (self.state == .failed) {
            const info = self.err_info orelse HandshakeErrorInfo{ .code = .invalid_state, .reply_code = null };
            return .{ .err = .{ .code = info.code, .reply_code = info.reply_code, .consumed = 0 } };
        }
        if (self.state == .request_done or self.state == .streaming) {
            return .need_more;
        }
        self.state = .failed;
        self.err_info = .{ .code = .unexpected_eof, .reply_code = null };
        return .{ .err = .{ .code = .unexpected_eof, .reply_code = null, .consumed = 0 } };
    }

    /// Feeds a chunk of incoming bytes to the handshake state machine.
    /// Returns a typed result indicating what action to take and the exact
    /// number of bytes consumed from `data`.
    pub fn feed(self: *Socks5Handshake, data: []const u8) FeedResult {
        if (self.state == .failed) {
            const info = self.err_info orelse HandshakeErrorInfo{ .code = .invalid_state, .reply_code = null };
            return .{
                .err = .{
                    .code = info.code,
                    .reply_code = info.reply_code,
                    .consumed = 0,
                },
            };
        }
        if (data.len == 0) return .need_more;

        switch (self.state) {
            .awaiting_greeting => return self.feedGreeting(data),
            .awaiting_request => return self.feedRequest(data),
            .request_done, .streaming => {
                return .{
                    .err = .{
                        .code = .invalid_state,
                        .reply_code = null,
                        .consumed = 0,
                    },
                };
            },
            .failed => unreachable,
        }
    }

    fn feedGreeting(self: *Socks5Handshake, data: []const u8) FeedResult {
        if (self.buf_len == 0) {
            if (expectedGreetingLen(data)) |total| {
                if (data.len >= total) {
                    const res = parseGreeting(data[0..total]);
                    return self.finishGreeting(res, total);
                }
            }

            // Incomplete greeting: buffer incoming chunk
            if (data.len > self.buf.len) {
                self.state = .failed;
                self.err_info = .{ .code = .buffer_overflow, .reply_code = null };
                return .{ .err = .{ .code = .buffer_overflow, .reply_code = null, .consumed = data.len } };
            }
            @memcpy(self.buf[0..data.len], data);
            self.buf_len = data.len;
            return .need_more;
        }

        // We already have some bytes buffered
        var data_used: usize = 0;
        while (expectedGreetingLen(self.buf[0..self.buf_len]) == null) {
            if (data_used >= data.len) return .need_more;
            self.buf[self.buf_len] = data[data_used];
            self.buf_len += 1;
            data_used += 1;
        }

        const total_needed = expectedGreetingLen(self.buf[0..self.buf_len]).?;
        if (total_needed > self.buf.len) {
            self.state = .failed;
            self.err_info = .{ .code = .buffer_overflow, .reply_code = null };
            self.buf_len = 0;
            return .{ .err = .{ .code = .buffer_overflow, .reply_code = null, .consumed = data_used } };
        }

        const remaining = total_needed - self.buf_len;
        const take = @min(remaining, data.len - data_used);
        @memcpy(self.buf[self.buf_len .. self.buf_len + take], data[data_used .. data_used + take]);
        self.buf_len += take;
        data_used += take;

        if (self.buf_len < total_needed) {
            return .need_more;
        }

        const res = parseGreeting(self.buf[0..total_needed]);
        self.buf_len = 0;
        return self.finishGreeting(res, data_used);
    }

    fn finishGreeting(self: *Socks5Handshake, res: GreetingParseResult, consumed: usize) FeedResult {
        switch (res) {
            .done => |d| {
                self.selected_method = d.selected_method;
                if (d.selected_method == .no_acceptable) {
                    self.state = .failed;
                    self.err_info = .{ .code = .no_acceptable_methods, .reply_code = null };
                    return .{
                        .send_method_reply = .{
                            .method = .no_acceptable,
                            .reply = encodeMethodSelection(.no_acceptable),
                            .consumed = consumed,
                        },
                    };
                }
                self.state = .awaiting_request;
                return .{
                    .send_method_reply = .{
                        .method = .no_auth,
                        .reply = encodeMethodSelection(.no_auth),
                        .consumed = consumed,
                    },
                };
            },
            .err => |e| {
                self.state = .failed;
                self.err_info = .{ .code = e.code, .reply_code = null };
                return .{
                    .err = .{
                        .code = e.code,
                        .reply_code = null,
                        .consumed = consumed,
                    },
                };
            },
            .need_more => unreachable,
        }
    }

    fn feedRequest(self: *Socks5Handshake, data: []const u8) FeedResult {
        if (self.buf_len == 0) {
            if (expectedRequestLen(data)) |total| {
                if (data.len >= total) {
                    const res = parseRequest(data[0..total]);
                    return self.finishRequest(res, total);
                }
            }

            // Incomplete request: buffer incoming chunk
            if (data.len > self.buf.len) {
                self.state = .failed;
                self.err_info = .{ .code = .buffer_overflow, .reply_code = .general_failure };
                return .{ .err = .{ .code = .buffer_overflow, .reply_code = .general_failure, .consumed = data.len } };
            }
            @memcpy(self.buf[0..data.len], data);
            self.buf_len = data.len;
            return .need_more;
        }

        // We already have some bytes buffered
        var data_used: usize = 0;
        while (expectedRequestLen(self.buf[0..self.buf_len]) == null) {
            if (data_used >= data.len) return .need_more;
            self.buf[self.buf_len] = data[data_used];
            self.buf_len += 1;
            data_used += 1;
        }

        const total_needed = expectedRequestLen(self.buf[0..self.buf_len]).?;
        if (total_needed > self.buf.len) {
            self.state = .failed;
            self.err_info = .{ .code = .buffer_overflow, .reply_code = .general_failure };
            self.buf_len = 0;
            return .{ .err = .{ .code = .buffer_overflow, .reply_code = .general_failure, .consumed = data_used } };
        }

        const remaining = total_needed - self.buf_len;
        const take = @min(remaining, data.len - data_used);
        @memcpy(self.buf[self.buf_len .. self.buf_len + take], data[data_used .. data_used + take]);
        self.buf_len += take;
        data_used += take;

        if (self.buf_len < total_needed) {
            return .need_more;
        }

        const res = parseRequest(self.buf[0..total_needed]);
        self.buf_len = 0;
        return self.finishRequest(res, data_used);
    }

    fn finishRequest(self: *Socks5Handshake, res: RequestParseResult, consumed: usize) FeedResult {
        switch (res) {
            .done => |d| {
                self.request = d.request;
                self.state = .request_done;
                return .{
                    .request_done = .{
                        .request = d.request,
                        .consumed = consumed,
                    },
                };
            },
            .err => |e| {
                self.state = .failed;
                self.err_info = .{ .code = e.code, .reply_code = e.reply_code };
                return .{
                    .err = .{
                        .code = e.code,
                        .reply_code = e.reply_code,
                        .consumed = consumed,
                    },
                };
            },
            .need_more => unreachable,
        }
    }
};

// ============================================================================
// Exhaustive Unit and Integration Tests
// ============================================================================

test "socks5 greeting parse valid No-Auth single method" {
    const raw = [_]u8{ 0x05, 0x01, 0x00 };
    const res = parseGreeting(&raw);
    try std.testing.expectEqual(AuthMethod.no_auth, res.done.selected_method);
    try std.testing.expectEqual(@as(u8, 1), res.done.methods_count);
    try std.testing.expectEqual(@as(usize, 3), res.done.consumed);
}

test "socks5 greeting parse multiple methods with No-Auth" {
    const raw = [_]u8{ 0x05, 0x03, 0x02, 0x01, 0x00 };
    const res = parseGreeting(&raw);
    try std.testing.expectEqual(AuthMethod.no_auth, res.done.selected_method);
    try std.testing.expectEqual(@as(u8, 3), res.done.methods_count);
    try std.testing.expectEqual(@as(usize, 5), res.done.consumed);
}

test "socks5 greeting parse no acceptable methods (0xFF)" {
    const raw = [_]u8{ 0x05, 0x02, 0x01, 0x02 }; // GSSAPI and USER_PASS, no No-Auth
    const res = parseGreeting(&raw);
    try std.testing.expectEqual(AuthMethod.no_acceptable, res.done.selected_method);
    try std.testing.expectEqual(@as(u8, 2), res.done.methods_count);
    try std.testing.expectEqual(@as(usize, 4), res.done.consumed);
}

test "socks5 greeting parse max 255 methods with No-Auth at the end" {
    var raw: [257]u8 = undefined;
    raw[0] = 0x05;
    raw[1] = 255;
    @memset(raw[2..256], 0x02);
    raw[256] = 0x00; // No-Auth at the very last index

    const res = parseGreeting(&raw);
    try std.testing.expectEqual(AuthMethod.no_auth, res.done.selected_method);
    try std.testing.expectEqual(@as(u8, 255), res.done.methods_count);
    try std.testing.expectEqual(@as(usize, 257), res.done.consumed);
}

test "socks5 greeting error cases: bad version, empty methods, truncated" {
    // Bad version
    const bad_ver = [_]u8{ 0x04, 0x01, 0x00 };
    const r_ver = parseGreeting(&bad_ver);
    try std.testing.expectEqual(HandshakeError.unsupported_version, r_ver.err.code);
    try std.testing.expectEqual(@as(usize, 1), r_ver.err.consumed);

    // Empty methods
    const empty_m = [_]u8{ 0x05, 0x00 };
    const r_empty = parseGreeting(&empty_m);
    try std.testing.expectEqual(HandshakeError.empty_methods, r_empty.err.code);
    try std.testing.expectEqual(@as(usize, 2), r_empty.err.consumed);

    // Truncated (need more)
    const trunc1 = [_]u8{0x05};
    const r_tr1 = parseGreeting(&trunc1);
    try std.testing.expect(r_tr1 == .need_more);

    const trunc2 = [_]u8{ 0x05, 0x03, 0x01 };
    const r_tr2 = parseGreeting(&trunc2);
    try std.testing.expectEqual(@as(usize, 2), r_tr2.need_more);
}

test "socks5 request parse IPv4 valid endpoints" {
    // 127.0.0.1:8080
    const raw = [_]u8{ 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90 };
    const res = parseRequest(&raw);
    try std.testing.expectEqual(Command.connect, res.done.request.command);
    try std.testing.expectEqual(@as(u16, 8080), res.done.request.endpoint.port);
    try std.testing.expectEqual(AddressType.ipv4, res.done.request.endpoint.address.addressType());
    try std.testing.expectEqual([_]u8{ 127, 0, 0, 1 }, res.done.request.endpoint.address.ipv4);
    try std.testing.expectEqual(@as(usize, 10), res.done.consumed);

    // 0.0.0.0:0 and 255.255.255.255:65535 boundary values
    const raw_zero = [_]u8{ 0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
    const r_zero = parseRequest(&raw_zero);
    try std.testing.expectEqual(@as(u16, 0), r_zero.done.request.endpoint.port);
    try std.testing.expectEqual([_]u8{ 0, 0, 0, 0 }, r_zero.done.request.endpoint.address.ipv4);

    const raw_max = [_]u8{ 0x05, 0x01, 0x00, 0x01, 255, 255, 255, 255, 0xFF, 0xFF };
    const r_max = parseRequest(&raw_max);
    try std.testing.expectEqual(@as(u16, 65535), r_max.done.request.endpoint.port);
    try std.testing.expectEqual([_]u8{ 255, 255, 255, 255 }, r_max.done.request.endpoint.address.ipv4);
}

test "socks5 request parse IPv6 valid endpoints" {
    // ::1:443
    var raw: [22]u8 = undefined;
    raw[0] = 0x05;
    raw[1] = 0x01; // CONNECT
    raw[2] = 0x00; // RSV
    raw[3] = 0x04; // IPv6
    @memset(raw[4..19], 0);
    raw[19] = 1; // ::1
    raw[20] = 0x01;
    raw[21] = 0xBB; // port 443

    const res = parseRequest(&raw);
    try std.testing.expectEqual(Command.connect, res.done.request.command);
    try std.testing.expectEqual(@as(u16, 443), res.done.request.endpoint.port);
    try std.testing.expectEqual(AddressType.ipv6, res.done.request.endpoint.address.addressType());
    try std.testing.expectEqual(@as(u8, 1), res.done.request.endpoint.address.ipv6[15]);
    try std.testing.expectEqual(@as(usize, 22), res.done.consumed);
}

test "socks5 request parse domain valid endpoints (short, medium, max 255 bytes)" {
    // "example.com":80
    const dname = "example.com";
    var raw: [7 + dname.len]u8 = undefined;
    raw[0] = 0x05;
    raw[1] = 0x01;
    raw[2] = 0x00;
    raw[3] = 0x03; // DOMAIN
    raw[4] = @intCast(dname.len);
    @memcpy(raw[5 .. 5 + dname.len], dname);
    raw[5 + dname.len] = 0x00;
    raw[6 + dname.len] = 80;

    const res = parseRequest(&raw);
    try std.testing.expectEqual(Command.connect, res.done.request.command);
    try std.testing.expectEqual(@as(u16, 80), res.done.request.endpoint.port);
    try std.testing.expectEqual(AddressType.domain, res.done.request.endpoint.address.addressType());
    try std.testing.expect(res.done.request.endpoint.address.domain.eql(dname));
    try std.testing.expectEqual(raw.len, res.done.consumed);

    // Single-char domain "a":53
    const raw_short = [_]u8{ 0x05, 0x01, 0x00, 0x03, 1, 'a', 0x00, 53 };
    const r_short = parseRequest(&raw_short);
    try std.testing.expect(r_short.done.request.endpoint.address.domain.eql("a"));
    try std.testing.expectEqual(@as(u16, 53), r_short.done.request.endpoint.port);

    // Max 255-char domain
    var raw_max: [7 + 255]u8 = undefined;
    raw_max[0] = 0x05;
    raw_max[1] = 0x01;
    raw_max[2] = 0x00;
    raw_max[3] = 0x03;
    raw_max[4] = 255;
    @memset(raw_max[5..260], 'x');
    raw_max[260] = 0x1F;
    raw_max[261] = 0x90; // 8080

    const r_max = parseRequest(&raw_max);
    try std.testing.expectEqual(@as(u8, 255), r_max.done.request.endpoint.address.domain.len);
    try std.testing.expectEqual(@as(u16, 8080), r_max.done.request.endpoint.port);
    try std.testing.expectEqual(@as(usize, 262), r_max.done.consumed);
}

test "socks5 request parse unsupported commands (BIND, UDP_ASSOCIATE, unknown)" {
    // BIND (0x02)
    const raw_bind = [_]u8{ 0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80 };
    const r_bind = parseRequest(&raw_bind);
    try std.testing.expectEqual(HandshakeError.unsupported_command, r_bind.err.code);
    try std.testing.expectEqual(ReplyCode.command_not_supported, r_bind.err.reply_code);
    try std.testing.expectEqual(@as(usize, 2), r_bind.err.consumed);

    // UDP ASSOCIATE (0x03)
    const raw_udp = [_]u8{ 0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0, 80 };
    const r_udp = parseRequest(&raw_udp);
    try std.testing.expectEqual(HandshakeError.unsupported_command, r_udp.err.code);
    try std.testing.expectEqual(ReplyCode.command_not_supported, r_udp.err.reply_code);

    // Unknown command (0x99)
    const raw_unk = [_]u8{ 0x05, 0x99, 0x00, 0x01, 127, 0, 0, 1, 0, 80 };
    const r_unk = parseRequest(&raw_unk);
    try std.testing.expectEqual(HandshakeError.unsupported_command, r_unk.err.code);
    try std.testing.expectEqual(ReplyCode.command_not_supported, r_unk.err.reply_code);
}

test "socks5 request parse unsupported address types and malformed fields" {
    // Bad version in request
    const raw_ver = [_]u8{ 0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80 };
    const r_ver = parseRequest(&raw_ver);
    try std.testing.expectEqual(HandshakeError.unsupported_version, r_ver.err.code);
    try std.testing.expectEqual(@as(usize, 1), r_ver.err.consumed);

    // Bad reserved byte (RSV != 0)
    const raw_rsv = [_]u8{ 0x05, 0x01, 0xFF, 0x01, 127, 0, 0, 1, 0, 80 };
    const r_rsv = parseRequest(&raw_rsv);
    try std.testing.expectEqual(HandshakeError.malformed_reserved, r_rsv.err.code);
    try std.testing.expectEqual(ReplyCode.general_failure, r_rsv.err.reply_code);
    try std.testing.expectEqual(@as(usize, 3), r_rsv.err.consumed);

    // Unsupported address type (e.g. 0x02, 0x05, 0xFF)
    const raw_atyp = [_]u8{ 0x05, 0x01, 0x00, 0x02, 127, 0, 0, 1, 0, 80 };
    const r_atyp = parseRequest(&raw_atyp);
    try std.testing.expectEqual(HandshakeError.unsupported_address_type, r_atyp.err.code);
    try std.testing.expectEqual(ReplyCode.address_type_not_supported, r_atyp.err.reply_code);
    try std.testing.expectEqual(@as(usize, 4), r_atyp.err.consumed);

    // Domain length 0 (malformed)
    const raw_dzero = [_]u8{ 0x05, 0x01, 0x00, 0x03, 0x00, 0, 80 };
    const r_dzero = parseRequest(&raw_dzero);
    try std.testing.expectEqual(HandshakeError.malformed_domain, r_dzero.err.code);
    try std.testing.expectEqual(ReplyCode.general_failure, r_dzero.err.reply_code);
    try std.testing.expectEqual(@as(usize, 5), r_dzero.err.consumed);
}

test "socks5 encode method selection exact bytes" {
    const s_ok = encodeMethodSelection(.no_auth);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x05, 0x00 }, &s_ok);

    const s_fail = encodeMethodSelection(.no_acceptable);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x05, 0xFF }, &s_fail);
}

test "socks5 encode default replies exact bytes" {
    const rep_ok = encodeDefaultReply(.succeeded);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, &rep_ok);

    const rep_cmd = encodeDefaultReply(.command_not_supported);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, &rep_cmd);

    const rep_atyp = encodeDefaultReply(.address_type_not_supported);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, &rep_atyp);

    const rep_refused = encodeDefaultReply(.connection_refused);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, &rep_refused);

    const rep_gen = encodeDefaultReply(.general_failure);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, &rep_gen);
}

test "socks5 encode replies with custom IPv4, IPv6, Domain endpoints" {
    var buf: [300]u8 = undefined;

    // IPv4 bound reply
    const ep_v4 = TargetEndpoint.initIpv4([_]u8{ 192, 168, 1, 10 }, 1080);
    const enc_v4 = try encodeReply(&buf, .succeeded, ep_v4);
    const exp_v4 = [_]u8{ 0x05, 0x00, 0x00, 0x01, 192, 168, 1, 10, 0x04, 0x38 };
    try std.testing.expectEqualSlices(u8, &exp_v4, enc_v4);

    // IPv6 bound reply
    var ip6: [16]u8 = undefined;
    @memset(&ip6, 0);
    ip6[15] = 1;
    const ep_v6 = TargetEndpoint.initIpv6(ip6, 8080);
    const enc_v6 = try encodeReply(&buf, .succeeded, ep_v6);
    try std.testing.expectEqual(@as(usize, 22), enc_v6.len);
    try std.testing.expectEqual(@as(u8, 0x04), enc_v6[3]);
    try std.testing.expectEqual(@as(u8, 1), enc_v6[19]);
    try std.testing.expectEqual(@as(u16, 8080), std.mem.readInt(u16, enc_v6[20..22][0..2], .big));

    // Domain bound reply
    const ep_domain = try TargetEndpoint.initDomain("proxy.local", 9000);
    const enc_d = try encodeReply(&buf, .succeeded, ep_domain);
    try std.testing.expectEqual(@as(usize, 4 + 1 + 11 + 2), enc_d.len);
    try std.testing.expectEqual(@as(u8, 0x03), enc_d[3]);
    try std.testing.expectEqual(@as(u8, 11), enc_d[4]);
    try std.testing.expectEqualStrings("proxy.local", enc_d[5..16]);
    try std.testing.expectEqual(@as(u16, 9000), std.mem.readInt(u16, enc_d[16..18][0..2], .big));

    // Buffer too small error
    var tiny: [5]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, encodeReply(&tiny, .succeeded, ep_v4));
}

test "socks5 handshake byte-by-byte feed across full IPv4 handshake" {
    var hs = Socks5Handshake.init();

    // Stream: Greeting (3 bytes) -> Request IPv4 (10 bytes)
    const greeting_bytes = [_]u8{ 0x05, 0x01, 0x00 };
    const req_bytes = [_]u8{ 0x05, 0x01, 0x00, 0x01, 10, 0, 0, 1, 0x01, 0xBB }; // 10.0.0.1:443

    // Feed greeting byte-by-byte
    for (greeting_bytes, 0..) |b, idx| {
        const slice = [_]u8{b};
        const r = hs.feed(&slice);
        if (idx < greeting_bytes.len - 1) {
            try std.testing.expectEqual(FeedResult.need_more, r);
            try std.testing.expectEqual(HandshakeState.awaiting_greeting, hs.state);
        } else {
            try std.testing.expect(r == .send_method_reply);
            try std.testing.expectEqual(AuthMethod.no_auth, r.send_method_reply.method);
            try std.testing.expectEqualSlices(u8, &[_]u8{ 0x05, 0x00 }, &r.send_method_reply.reply);
            try std.testing.expectEqual(@as(usize, 1), r.send_method_reply.consumed);
            try std.testing.expectEqual(HandshakeState.awaiting_request, hs.state);
        }
    }

    // Feed request byte-by-byte
    for (req_bytes, 0..) |b, idx| {
        const slice = [_]u8{b};
        const r = hs.feed(&slice);
        if (idx < req_bytes.len - 1) {
            try std.testing.expectEqual(FeedResult.need_more, r);
            try std.testing.expectEqual(HandshakeState.awaiting_request, hs.state);
        } else {
            try std.testing.expect(r == .request_done);
            try std.testing.expectEqual(Command.connect, r.request_done.request.command);
            try std.testing.expectEqual(@as(u16, 443), r.request_done.request.endpoint.port);
            try std.testing.expectEqual([_]u8{ 10, 0, 0, 1 }, r.request_done.request.endpoint.address.ipv4);
            try std.testing.expectEqual(@as(usize, 1), r.request_done.consumed);
            try std.testing.expect(hs.isDone());
        }
    }
}

test "socks5 handshake byte-by-byte feed across full IPv6 handshake" {
    var hs = Socks5Handshake.init();

    const greeting_bytes = [_]u8{ 0x05, 0x02, 0x02, 0x00 }; // UserPass + NoAuth
    var req_bytes: [22]u8 = undefined;
    req_bytes[0] = 0x05;
    req_bytes[1] = 0x01;
    req_bytes[2] = 0x00;
    req_bytes[3] = 0x04; // IPv6
    @memset(req_bytes[4..20], 0xAA);
    req_bytes[20] = 0x22;
    req_bytes[21] = 0xB8; // 8888

    // Greeting 1 byte at a time
    for (greeting_bytes, 0..) |b, idx| {
        const slice = [_]u8{b};
        const r = hs.feed(&slice);
        if (idx < greeting_bytes.len - 1) {
            try std.testing.expectEqual(FeedResult.need_more, r);
        } else {
            try std.testing.expect(r == .send_method_reply);
            try std.testing.expectEqual(AuthMethod.no_auth, r.send_method_reply.method);
        }
    }

    // Request 1 byte at a time
    for (req_bytes, 0..) |b, idx| {
        const slice = [_]u8{b};
        const r = hs.feed(&slice);
        if (idx < req_bytes.len - 1) {
            try std.testing.expectEqual(FeedResult.need_more, r);
        } else {
            try std.testing.expect(r == .request_done);
            try std.testing.expectEqual(@as(u16, 8888), r.request_done.request.endpoint.port);
            try std.testing.expectEqual(@as(u8, 0xAA), r.request_done.request.endpoint.address.ipv6[0]);
        }
    }
}

test "socks5 handshake byte-by-byte feed across full Domain handshake" {
    var hs = Socks5Handshake.init();

    const greeting_bytes = [_]u8{ 0x05, 0x01, 0x00 };
    const dname = "api.virm.io";
    var req_bytes: [7 + dname.len]u8 = undefined;
    req_bytes[0] = 0x05;
    req_bytes[1] = 0x01;
    req_bytes[2] = 0x00;
    req_bytes[3] = 0x03;
    req_bytes[4] = @intCast(dname.len);
    @memcpy(req_bytes[5 .. 5 + dname.len], dname);
    req_bytes[5 + dname.len] = 0x01;
    req_bytes[6 + dname.len] = 0xBB; // 443

    for (greeting_bytes) |b| {
        _ = hs.feed(&[_]u8{b});
    }

    for (req_bytes, 0..) |b, idx| {
        const r = hs.feed(&[_]u8{b});
        if (idx < req_bytes.len - 1) {
            try std.testing.expectEqual(FeedResult.need_more, r);
        } else {
            try std.testing.expect(r == .request_done);
            try std.testing.expect(r.request_done.request.endpoint.address.domain.eql(dname));
            try std.testing.expectEqual(@as(u16, 443), r.request_done.request.endpoint.port);
        }
    }
}

test "socks5 handshake arbitrary split points (every boundary from 1 to N-1)" {
    const greeting = [_]u8{ 0x05, 0x01, 0x00 };
    const request = [_]u8{ 0x05, 0x01, 0x00, 0x01, 172, 16, 0, 1, 0x00, 80 };

    // Test every split point of greeting
    var g_split: usize = 1;
    while (g_split < greeting.len) : (g_split += 1) {
        var hs = Socks5Handshake.init();
        const r1 = hs.feed(greeting[0..g_split]);
        try std.testing.expectEqual(FeedResult.need_more, r1);

        const r2 = hs.feed(greeting[g_split..]);
        try std.testing.expect(r2 == .send_method_reply);
        try std.testing.expectEqual(greeting.len - g_split, r2.send_method_reply.consumed);
    }

    // Test every split point of request
    var r_split: usize = 1;
    while (r_split < request.len) : (r_split += 1) {
        var hs = Socks5Handshake.init();
        _ = hs.feed(&greeting);

        const r1 = hs.feed(request[0..r_split]);
        try std.testing.expectEqual(FeedResult.need_more, r1);

        const r2 = hs.feed(request[r_split..]);
        try std.testing.expect(r2 == .request_done);
        try std.testing.expectEqual(request.len - r_split, r2.request_done.consumed);
        try std.testing.expectEqual(@as(u16, 80), r2.request_done.request.endpoint.port);
    }
}

test "socks5 handshake coalesced greeting and request in single chunk" {
    const greeting = [_]u8{ 0x05, 0x01, 0x00 };
    const request = [_]u8{ 0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x00, 53 };

    var coalesced: [greeting.len + request.len]u8 = undefined;
    @memcpy(coalesced[0..greeting.len], &greeting);
    @memcpy(coalesced[greeting.len..], &request);

    var hs = Socks5Handshake.init();
    var offset: usize = 0;

    // First feed parses greeting
    const r1 = hs.feed(coalesced[offset..]);
    try std.testing.expect(r1 == .send_method_reply);
    try std.testing.expectEqual(greeting.len, r1.send_method_reply.consumed);
    offset += r1.send_method_reply.consumed;

    // Second feed parses request
    const r2 = hs.feed(coalesced[offset..]);
    try std.testing.expect(r2 == .request_done);
    try std.testing.expectEqual(request.len, r2.request_done.consumed);
    try std.testing.expectEqual(@as(u16, 53), r2.request_done.request.endpoint.port);
    try std.testing.expectEqual([_]u8{ 1, 1, 1, 1 }, r2.request_done.request.endpoint.address.ipv4);
    offset += r2.request_done.consumed;

    try std.testing.expectEqual(coalesced.len, offset);
}

test "socks5 handshake coalesced greeting, request, and relay payload (exact payload preserved)" {
    const greeting = [_]u8{ 0x05, 0x01, 0x00 };
    const request = [_]u8{ 0x05, 0x01, 0x00, 0x01, 8, 8, 8, 8, 0x01, 0xBB }; // 8.8.8.8:443
    const payload = "CONNECT_STREAM_PAYLOAD_FOR_RELAY_VERIFICATION_1234567890";

    const total_len = greeting.len + request.len + payload.len;
    var coalesced: [total_len]u8 = undefined;
    @memcpy(coalesced[0..greeting.len], &greeting);
    @memcpy(coalesced[greeting.len .. greeting.len + request.len], &request);
    @memcpy(coalesced[greeting.len + request.len ..], payload);

    var hs = Socks5Handshake.init();
    var offset: usize = 0;

    // Step 1: Greeting
    const r1 = hs.feed(coalesced[offset..]);
    try std.testing.expect(r1 == .send_method_reply);
    try std.testing.expectEqual(greeting.len, r1.send_method_reply.consumed);
    offset += r1.send_method_reply.consumed;

    // Step 2: Request
    const r2 = hs.feed(coalesced[offset..]);
    try std.testing.expect(r2 == .request_done);
    try std.testing.expectEqual(request.len, r2.request_done.consumed);
    offset += r2.request_done.consumed;

    // Step 3: Exact leftover payload for future relay
    const leftover = coalesced[offset..];
    try std.testing.expectEqualStrings(payload, leftover);
}

test "socks5 handshake coalesced request and relay payload" {
    var hs = Socks5Handshake.init();
    _ = hs.feed(&[_]u8{ 0x05, 0x01, 0x00 });

    const request = [_]u8{ 0x05, 0x01, 0x00, 0x01, 192, 168, 0, 1, 0x00, 22 };
    const payload = "SSH-2.0-OpenSSH_9.0\r\n";

    var coalesced: [request.len + payload.len]u8 = undefined;
    @memcpy(coalesced[0..request.len], &request);
    @memcpy(coalesced[request.len..], payload);

    const r = hs.feed(&coalesced);
    try std.testing.expect(r == .request_done);
    try std.testing.expectEqual(request.len, r.request_done.consumed);
    try std.testing.expectEqual(@as(u16, 22), r.request_done.request.endpoint.port);

    const leftover = coalesced[r.request_done.consumed..];
    try std.testing.expectEqualStrings(payload, leftover);
}

test "socks5 handshake cross-boundary chunking with trailing payload" {
    // Chunk 1: greeting[0..2]
    // Chunk 2: greeting[2..3] ++ request[0..5]
    // Chunk 3: request[5..10] ++ payload
    const greeting = [_]u8{ 0x05, 0x01, 0x00 };
    const request = [_]u8{ 0x05, 0x01, 0x00, 0x01, 10, 10, 10, 10, 0x00, 80 };
    const payload = "GET /index.html HTTP/1.1\r\nHost: test\r\n\r\n";

    var hs = Socks5Handshake.init();

    // Chunk 1
    const r1 = hs.feed(greeting[0..2]);
    try std.testing.expectEqual(FeedResult.need_more, r1);

    // Chunk 2 contains end of greeting and start of request
    var chunk2: [1 + 5]u8 = undefined;
    chunk2[0] = greeting[2];
    @memcpy(chunk2[1..], request[0..5]);

    var c2_off: usize = 0;
    const r2_a = hs.feed(chunk2[c2_off..]);
    try std.testing.expect(r2_a == .send_method_reply);
    try std.testing.expectEqual(@as(usize, 1), r2_a.send_method_reply.consumed);
    c2_off += r2_a.send_method_reply.consumed;

    const r2_b = hs.feed(chunk2[c2_off..]);
    try std.testing.expectEqual(FeedResult.need_more, r2_b);

    // Chunk 3 contains end of request and payload
    var chunk3: [5 + payload.len]u8 = undefined;
    @memcpy(chunk3[0..5], request[5..10]);
    @memcpy(chunk3[5..], payload);

    var c3_off: usize = 0;
    const r3 = hs.feed(chunk3[c3_off..]);
    try std.testing.expect(r3 == .request_done);
    try std.testing.expectEqual(@as(usize, 5), r3.request_done.consumed);
    c3_off += r3.request_done.consumed;

    // Remaining slice in chunk 3 is byte-exact payload
    const leftover = chunk3[c3_off..];
    try std.testing.expectEqualStrings(payload, leftover);
}

test "socks5 handshake EOF handling" {
    // EOF while expecting greeting
    var hs1 = Socks5Handshake.init();
    _ = hs1.feed(&[_]u8{0x05});
    const e1 = hs1.feedEof();
    try std.testing.expect(e1 == .err);
    try std.testing.expectEqual(HandshakeError.unexpected_eof, e1.err.code);
    try std.testing.expect(hs1.isFailed());

    // EOF while expecting request
    var hs2 = Socks5Handshake.init();
    _ = hs2.feed(&[_]u8{ 0x05, 0x01, 0x00 });
    _ = hs2.feed(&[_]u8{ 0x05, 0x01 });
    const e2 = hs2.feedEof();
    try std.testing.expect(e2 == .err);
    try std.testing.expectEqual(HandshakeError.unexpected_eof, e2.err.code);
    try std.testing.expect(hs2.isFailed());

    // EOF after request done is ignored / need_more
    var hs3 = Socks5Handshake.init();
    _ = hs3.feed(&[_]u8{ 0x05, 0x01, 0x00 });
    _ = hs3.feed(&[_]u8{ 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80 });
    const e3 = hs3.feedEof();
    try std.testing.expectEqual(FeedResult.need_more, e3);
    try std.testing.expect(hs3.isDone());
}

test "socks5 handshake large coalesced buffer (64 KiB) preserves exact payload" {
    var hs = Socks5Handshake.init();
    const greeting = [_]u8{ 0x05, 0x01, 0x00 };
    const request = [_]u8{ 0x05, 0x01, 0x00, 0x01, 10, 0, 0, 1, 0x1F, 0x90 }; // 10.0.0.1:8080

    const payload_size = 64 * 1024;
    const total_size = greeting.len + request.len + payload_size;
    const full_buf = try std.testing.allocator.alloc(u8, total_size);
    defer std.testing.allocator.free(full_buf);

    @memcpy(full_buf[0..greeting.len], &greeting);
    @memcpy(full_buf[greeting.len .. greeting.len + request.len], &request);
    for (full_buf[greeting.len + request.len ..], 0..) |*b, idx| {
        b.* = @intCast(idx % 251);
    }

    var offset: usize = 0;
    const r1 = hs.feed(full_buf[offset..]);
    try std.testing.expect(r1 == .send_method_reply);
    try std.testing.expectEqual(greeting.len, r1.send_method_reply.consumed);
    offset += r1.send_method_reply.consumed;

    const r2 = hs.feed(full_buf[offset..]);
    try std.testing.expect(r2 == .request_done);
    try std.testing.expectEqual(request.len, r2.request_done.consumed);
    try std.testing.expectEqual(@as(u16, 8080), r2.request_done.request.endpoint.port);
    offset += r2.request_done.consumed;

    const leftover = full_buf[offset..];
    try std.testing.expectEqual(payload_size, leftover.len);
    for (leftover, 0..) |b, idx| {
        try std.testing.expectEqual(@as(u8, @intCast(idx % 251)), b);
    }
}

test "socks5 handshake reset and reuse" {
    var hs = Socks5Handshake.init();
    _ = hs.feed(&[_]u8{ 0x05, 0x01, 0x00 });
    _ = hs.feed(&[_]u8{ 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80 });
    try std.testing.expect(hs.isDone());

    hs.reset();
    try std.testing.expectEqual(HandshakeState.awaiting_greeting, hs.state);
    try std.testing.expect(!hs.isDone());
    try std.testing.expect(!hs.isFailed());

    // Second connection parsed successfully
    _ = hs.feed(&[_]u8{ 0x05, 0x01, 0x00 });
    const r = hs.feed(&[_]u8{ 0x05, 0x01, 0x00, 0x01, 10, 0, 0, 1, 0, 22 });
    try std.testing.expect(r == .request_done);
    try std.testing.expectEqual(@as(u16, 22), r.request_done.request.endpoint.port);
}

test "socks5 endpoint and address formatting on Zig 0.16" {
    var buf: [256]u8 = undefined;

    // IPv4 endpoint and address
    const ep_v4 = TargetEndpoint.initIpv4(.{ 127, 0, 0, 1 }, 8080);
    const str_v4 = try std.fmt.bufPrint(&buf, "{f}", .{ep_v4});
    try std.testing.expectEqualStrings("127.0.0.1:8080", str_v4);

    const str_addr_v4 = try std.fmt.bufPrint(&buf, "{f}", .{ep_v4.address});
    try std.testing.expectEqualStrings("127.0.0.1", str_addr_v4);

    // IPv6 endpoint and address
    var ip6: [16]u8 = [_]u8{0} ** 16;
    ip6[15] = 1;
    const ep_v6 = TargetEndpoint.initIpv6(ip6, 443);
    const str_v6 = try std.fmt.bufPrint(&buf, "{f}", .{ep_v6});
    try std.testing.expectEqualStrings("[0:0:0:0:0:0:0:1]:443", str_v6);

    const str_addr_v6 = try std.fmt.bufPrint(&buf, "{f}", .{ep_v6.address});
    try std.testing.expectEqualStrings("0:0:0:0:0:0:0:1", str_addr_v6);

    // Domain endpoint and address
    const ep_domain = try TargetEndpoint.initDomain("example.com", 9000);
    const str_d = try std.fmt.bufPrint(&buf, "{f}", .{ep_domain});
    try std.testing.expectEqualStrings("example.com:9000", str_d);

    const str_addr_d = try std.fmt.bufPrint(&buf, "{f}", .{ep_domain.address});
    try std.testing.expectEqualStrings("example.com", str_addr_d);
}

test "socks5 rejection remains available after client EOF" {
    var hs = Socks5Handshake.init();
    _ = hs.feed(&[_]u8{ 5, 1, 0 });
    const rejected = hs.feed(&[_]u8{ 5, 2 });
    try std.testing.expect(rejected == .err);
    try std.testing.expectEqual(HandshakeError.unsupported_command, rejected.err.code);
    try std.testing.expect(hs.getErrorReply() != null);

    const eof = hs.feedEof();
    try std.testing.expect(eof == .err);
    try std.testing.expectEqual(HandshakeError.unsupported_command, eof.err.code);
    try std.testing.expect(hs.getErrorReply() != null);
}

test "socks5 empty feed cannot revive a failed handshake" {
    var hs = Socks5Handshake.init();
    _ = hs.feed(&[_]u8{ 5, 1, 0 });
    _ = hs.feed(&[_]u8{ 5, 2 });
    const r = hs.feed("");
    try std.testing.expect(r == .err);
    try std.testing.expectEqual(HandshakeError.unsupported_command, r.err.code);
}

test "socks5 request domain owns bytes independently of caller input" {
    var wire = [_]u8{ 5, 1, 0, 3, 3, 'a', 'b', 'c', 1, 187 };
    const parsed = parseRequest(&wire);
    try std.testing.expect(parsed == .done);
    const request = parsed.done.request;
    @memset(&wire, 0);
    try std.testing.expectEqualStrings("abc", request.endpoint.address.domain.slice());

    var hs = Socks5Handshake.init();
    _ = hs.feed(&[_]u8{ 5, 1, 0 });
    wire = .{ 5, 1, 0, 3, 3, 'a', 'b', 'c', 1, 187 };
    const r = hs.feed(&wire);
    try std.testing.expect(r == .request_done);
    @memset(&wire, 0);
    hs.reset();
    try std.testing.expectEqualStrings("abc", r.request_done.request.endpoint.address.domain.slice());
}

test "socks5 reply encoder rejects insufficient space without partial output" {
    var buf: [21]u8 = [_]u8{0xaa} ** 21;
    try std.testing.expectError(error.BufferTooSmall, encodeReply(&buf, .succeeded, TargetEndpoint.initIpv6([_]u8{0} ** 16, 443)));
    for (buf) |b| try std.testing.expectEqual(@as(u8, 0xaa), b);

    var bytes: [MAX_REQUEST_LEN]u8 = undefined;
    const address = [_]u8{'x'} ** 255;
    const bnd = try TargetEndpoint.initDomain(&address, 65535);
    const r = try encodeReply(&bytes, .succeeded, bnd);
    try std.testing.expectEqual(MAX_REQUEST_LEN, r.len);
    try std.testing.expectEqual(@as(u8, 255), r[4]);
    try std.testing.expectEqualSlices(u8, &address, r[5..260]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 255, 255 }, r[260..]);
}

test "socks5 zero dynamic allocations verified" {
    var hs = Socks5Handshake.init();
    _ = hs.feed(&[_]u8{ 0x05, 0x01, 0x00 });
    const r = hs.feed(&[_]u8{ 0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x12, 0x34 });
    try std.testing.expect(r == .request_done);
}

const probe_greeting = [_]u8{ 5, 1, 0 };

fn driveProbe(hs: *Socks5Handshake, chunk: []const u8, absolute_start: usize, header_end: usize) !void {
    var used: usize = 0;
    while (used < chunk.len and !hs.isDone()) {
        const result = hs.feed(chunk[used..]);
        switch (result) {
            .need_more => used = chunk.len,
            .send_method_reply => |r| {
                try std.testing.expectEqual(AuthMethod.no_auth, r.method);
                try std.testing.expect(r.consumed > 0 and r.consumed <= chunk.len - used);
                used += r.consumed;
                try std.testing.expectEqual(@as(usize, 3), absolute_start + used);
            },
            .request_done => |r| {
                try std.testing.expect(r.consumed > 0 and r.consumed <= chunk.len - used);
                used += r.consumed;
                try std.testing.expectEqual(header_end, absolute_start + used);
                try std.testing.expectEqual(@as(u16, 443), r.request.endpoint.port);
            },
            .err => return error.UnexpectedParseError,
        }
    }
}

fn testAllSplits(request: []const u8) !void {
    var wire: [3 + MAX_REQUEST_LEN + 19]u8 = undefined;
    const end = probe_greeting.len + request.len;
    @memcpy(wire[0..3], &probe_greeting);
    @memcpy(wire[3..end], request);
    const payload = "EARLY_PAYLOAD_BYTES";
    @memcpy(wire[end .. end + payload.len], payload);
    for (1..end) |i| {
        for (i + 1..end + 1) |j| {
            var hs = Socks5Handshake.init();
            try driveProbe(&hs, wire[0..i], 0, end);
            try driveProbe(&hs, wire[i..j], i, end);
            try driveProbe(&hs, wire[j .. end + payload.len], j, end);
            try std.testing.expect(hs.isDone());
            try std.testing.expect(hs.buf_len <= MAX_REQUEST_LEN);
            try std.testing.expectEqualStrings(payload, wire[end .. end + payload.len]);
        }
    }
}

test "socks5 all three-chunk splits preserve max domain and maximum greeting boundaries" {
    var request: [MAX_REQUEST_LEN]u8 = undefined;
    @memcpy(request[0..5], &[_]u8{ 5, 1, 0, 3, 255 });
    @memset(request[5..260], 'x');
    request[260] = 1;
    request[261] = 187;
    try testAllSplits(&request);

    var g: [MAX_GREETING_LEN]u8 = undefined;
    g[0] = 5;
    g[1] = 255;
    @memset(g[2..], 2);
    g[256] = 0;
    for (1..g.len) |split| {
        var hs = Socks5Handshake.init();
        try std.testing.expect(hs.feed(g[0..split]) == .need_more);
        const r = hs.feed(g[split..]);
        try std.testing.expect(r == .send_method_reply);
        try std.testing.expectEqual(g.len - split, r.send_method_reply.consumed);
        try std.testing.expectEqual(AuthMethod.no_auth, r.send_method_reply.method);
    }
}

test "socks5 all three-chunk IPv4 IPv6 splits preserve payload" {
    try testAllSplits(&[_]u8{ 5, 1, 0, 1, 127, 0, 0, 1, 1, 187 });
    try testAllSplits(&[_]u8{ 5, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187 });
}
