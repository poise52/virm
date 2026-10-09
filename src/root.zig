//! Virm Core Root Module
const std = @import("std");

pub const net = struct {
    pub const buffer_pool = @import("net/buffer_pool.zig");
    pub const fifo_queue = @import("net/fifo_queue.zig");
    pub const tcp_lifecycle = @import("net/tcp_lifecycle.zig");
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
test {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(net);
    std.testing.refAllDecls(net.buffer_pool);
    std.testing.refAllDecls(net.fifo_queue);
    std.testing.refAllDecls(net.tcp_lifecycle);
}
