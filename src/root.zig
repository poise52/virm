//! Virm Core Root Module
const std = @import("std");

pub const platform = struct {
    pub const darwin = @import("platform/darwin.zig");
};

pub const net = struct {
    pub const buffer_pool = @import("net/buffer_pool.zig");
    pub const fifo_queue = @import("net/fifo_queue.zig");
    pub const tcp_lifecycle = @import("net/tcp_lifecycle.zig");
    pub const kqueue_reactor = @import("net/kqueue_reactor.zig");
    pub const tcp_relay = @import("net/tcp_relay.zig");
};

pub const protocol = struct {
    pub const socks5 = @import("protocol/socks5.zig");
};

// Re-export core networking abstractions
pub const WorkerBufferPool = net.buffer_pool.WorkerBufferPool;
pub const Buffer = net.buffer_pool.Buffer;
pub const BUFFER_SIZE = net.buffer_pool.BUFFER_SIZE;

pub const BoundedFifoQueue = net.fifo_queue.BoundedFifoQueue;
pub const MAX_QUEUE_BYTES = net.fifo_queue.MAX_QUEUE_BYTES;
pub const THROTTLE_THRESHOLD_BYTES = net.fifo_queue.THROTTLE_THRESHOLD_BYTES;
pub const RESUME_THRESHOLD_BYTES = net.fifo_queue.RESUME_THRESHOLD_BYTES;

pub const TcpLifecycle = net.tcp_lifecycle.TcpLifecycle;
pub const Direction = net.tcp_lifecycle.Direction;
pub const StreamState = net.tcp_lifecycle.StreamState;
pub const SessionStatus = net.tcp_lifecycle.SessionStatus;
pub const LifecycleAction = net.tcp_lifecycle.LifecycleAction;
pub const BufferPoolError = net.buffer_pool.BufferPoolError;
pub const QueueError = net.fifo_queue.QueueError;
pub const TcpLifecycleError = net.tcp_lifecycle.TcpLifecycleError;
pub const KqueueReactor = net.kqueue_reactor.KqueueReactor;
pub const TcpRelay = net.tcp_relay.TcpRelay;
pub const RelayConfig = net.tcp_relay.RelayConfig;

// Re-export SOCKS5 protocol abstractions
pub const socks5 = protocol.socks5;
pub const Socks5Handshake = socks5.Socks5Handshake;
pub const Socks5Request = socks5.Socks5Request;
pub const TargetAddress = socks5.TargetAddress;
pub const TargetEndpoint = socks5.TargetEndpoint;
pub const AuthMethod = socks5.AuthMethod;
pub const Command = socks5.Command;
pub const AddressType = socks5.AddressType;
pub const ReplyCode = socks5.ReplyCode;
pub const HandshakeState = socks5.HandshakeState;
pub const HandshakeError = socks5.HandshakeError;
pub const FeedResult = socks5.FeedResult;

test {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(platform);
    std.testing.refAllDecls(platform.darwin);
    std.testing.refAllDecls(net);
    std.testing.refAllDecls(net.buffer_pool);
    std.testing.refAllDecls(net.fifo_queue);
    std.testing.refAllDecls(net.tcp_lifecycle);
    std.testing.refAllDecls(net.kqueue_reactor);
    std.testing.refAllDecls(net.tcp_relay);
    std.testing.refAllDecls(protocol);
    std.testing.refAllDecls(protocol.socks5);
}
