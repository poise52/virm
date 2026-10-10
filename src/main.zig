//! Virm SOCKS5 Proxy Server Executable (M1a.4)

const std = @import("std");
const virm = @import("virm");
const darwin = virm.platform.darwin;
const Router = virm.Router;
const OutboundAction = virm.OutboundAction;
const Socks5Service = virm.Socks5Service;

fn parseAddress(str: []const u8) !struct { ip: [4]u8, port: u16 } {
    var it = std.mem.splitScalar(u8, str, ':');
    const ip_str = it.next() orelse return error.InvalidAddress;
    const port_str = it.next() orelse return error.InvalidAddress;
    if (it.next() != null) return error.InvalidAddress;

    var ip: [4]u8 = undefined;
    var oct_it = std.mem.splitScalar(u8, ip_str, '.');
    for (0..4) |i| {
        const part = oct_it.next() orelse return error.InvalidAddress;
        ip[i] = try std.fmt.parseInt(u8, part, 10);
    }
    if (oct_it.next() != null) return error.InvalidAddress;

    const port = try std.fmt.parseInt(u16, port_str, 10);
    return .{ .ip = ip, .port = port };
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    var listen_addr_str: []const u8 = "127.0.0.1:1080";
    var default_action: OutboundAction = .direct;

    var idx: usize = 1;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "--listen") or std.mem.eql(u8, arg, "-l")) {
            idx += 1;
            if (idx >= args.len) {
                std.debug.print("Error: missing value for --listen\n", .{});
                return error.InvalidArguments;
            }
            listen_addr_str = args[idx];
        } else if (std.mem.eql(u8, arg, "--default") or std.mem.eql(u8, arg, "-d")) {
            idx += 1;
            if (idx >= args.len) {
                std.debug.print("Error: missing value for --default\n", .{});
                return error.InvalidArguments;
            }
            const val = args[idx];
            if (std.ascii.eqlIgnoreCase(val, "direct")) {
                default_action = .direct;
            } else if (std.ascii.eqlIgnoreCase(val, "block")) {
                default_action = .block;
            } else {
                std.debug.print("Error: invalid default action '{s}' (must be 'direct' or 'block')\n", .{val});
                return error.InvalidArguments;
            }
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            std.debug.print(
                \\Usage: virm [options]
                \\
                \\Options:
                \\  --listen, -l <ip:port>      Listener address and port (default: 127.0.0.1:1080)
                \\  --default, -d <action>      Default outbound action: direct or block (default: direct)
                \\  --help, -h                  Display this help message
                \\
            , .{});
            return;
        } else {
            std.debug.print("Unknown argument: {s}. Use --help for usage.\n", .{arg});
            return error.InvalidArguments;
        }
    }

    const addr = try parseAddress(listen_addr_str);

    const listener_fd = try darwin.createNonBlockingTcpSocket();
    defer darwin.closeSocket(listener_fd);
    try darwin.setReuseAddress(listener_fd);

    const bind_addr = darwin.sockaddr_in{
        .port = std.mem.nativeToBig(u16, addr.port),
        .addr = @bitCast(addr.ip),
    };

    if (darwin.bind(listener_fd, @ptrCast(&bind_addr), @sizeOf(darwin.sockaddr_in)) < 0) {
        std.debug.print("Failed to bind listener on {s}\n", .{listen_addr_str});
        return error.BindFailed;
    }

    if (darwin.listen(listener_fd, 128) < 0) {
        std.debug.print("Failed to listen on {s}\n", .{listen_addr_str});
        return error.ListenFailed;
    }

    const router = Router.initStatic(&[_]virm.Rule{}, default_action);
    var service = try Socks5Service.init(arena, listener_fd, router, .{});
    defer service.deinit();

    std.debug.print(
        \\==================================================
        \\  Virm SOCKS5 Server (M1a.4)
        \\  Listening on {s}
        \\  Default outbound: {s}
        \\  Ready for SOCKS5 clients.
        \\==================================================
        \\
    , .{
        listen_addr_str,
        if (default_action == .direct) "DIRECT" else "BLOCK",
    });

    while (true) {
        _ = service.step(500) catch |err| {
            std.debug.print("Reactor step error: {s}\n", .{@errorName(err)});
            break;
        };
    }
}
