//! Routing Engine for Virm SOCKS5 Proxy
//!
//! Evaluates inbound target endpoints against an ordered list of rules
//! with exact domain, domain suffix (with boundary checking), IPv4/IPv6 CIDR,
//! and port matchers. All conditions within a single rule are combined via AND.
//! The first matching rule determines the outbound action; if no rule matches,
//! the explicit default outbound action is returned.
//!
//! Routing decisions perform strictly in-memory evaluation with ZERO DNS
//! or network operations.

const std = @import("std");
const socks5 = @import("../protocol/socks5.zig");

pub const TargetEndpoint = socks5.TargetEndpoint;
pub const TargetAddress = socks5.TargetAddress;

/// Action determining outbound routing policy.
pub const OutboundAction = enum {
    direct,
    block,
};

/// IPv4 Classless Inter-Domain Routing (CIDR) matcher.
pub const Ipv4Cidr = struct {
    prefix: [4]u8,
    prefix_len: u6, // 0..32

    pub fn init(prefix: [4]u8, prefix_len: u6) !Ipv4Cidr {
        if (prefix_len > 32) return error.InvalidPrefixLength;
        return .{
            .prefix = prefix,
            .prefix_len = prefix_len,
        };
    }

    /// Parses an IPv4 CIDR string in the format "A.B.C.D/M" or "A.B.C.D" (assumes /32).
    pub fn parse(text: []const u8) !Ipv4Cidr {
        var it = std.mem.splitScalar(u8, text, '/');
        const ip_str = it.next() orelse return error.InvalidCidrFormat;
        const mask_str = it.next();

        if (it.next() != null) return error.InvalidCidrFormat;

        var ip: [4]u8 = undefined;
        var octet_it = std.mem.splitScalar(u8, ip_str, '.');
        for (0..4) |idx| {
            const part = octet_it.next() orelse return error.InvalidIpFormat;
            ip[idx] = try std.fmt.parseInt(u8, part, 10);
        }
        if (octet_it.next() != null) return error.InvalidIpFormat;

        const prefix_len: u6 = if (mask_str) |m| blk: {
            const val = try std.fmt.parseInt(u6, m, 10);
            if (val > 32) return error.InvalidPrefixLength;
            break :blk val;
        } else 32;

        return init(ip, prefix_len);
    }

    pub fn matches(self: Ipv4Cidr, ip: [4]u8) bool {
        if (self.prefix_len == 0) return true;
        const mask: u32 = if (self.prefix_len == 32)
            0xFFFF_FFFF
        else
            ~(@as(u32, 0xFFFF_FFFF) >> @as(u5, @intCast(self.prefix_len)));

        const prefix_val = std.mem.readInt(u32, &self.prefix, .big);
        const ip_val = std.mem.readInt(u32, &ip, .big);
        return (ip_val & mask) == (prefix_val & mask);
    }
};

/// IPv6 Classless Inter-Domain Routing (CIDR) matcher.
pub const Ipv6Cidr = struct {
    prefix: [16]u8,
    prefix_len: u8, // 0..128

    pub fn init(prefix: [16]u8, prefix_len: u8) !Ipv6Cidr {
        if (prefix_len > 128) return error.InvalidPrefixLength;
        return .{
            .prefix = prefix,
            .prefix_len = prefix_len,
        };
    }

    pub fn matches(self: Ipv6Cidr, ip: [16]u8) bool {
        if (self.prefix_len == 0) return true;
        const full_bytes = self.prefix_len / 8;
        const remaining_bits: u8 = self.prefix_len % 8;

        if (full_bytes > 0) {
            if (!std.mem.eql(u8, self.prefix[0..full_bytes], ip[0..full_bytes])) {
                return false;
            }
        }

        if (remaining_bits > 0) {
            const shift: u3 = @intCast(8 - remaining_bits);
            const mask: u8 = @as(u8, 0xFF) << shift;
            return (ip[full_bytes] & mask) == (self.prefix[full_bytes] & mask);
        }

        return true;
    }
};

/// Checks if `domain` matches `suffix` taking domain label boundaries into account.
/// E.g. "example.com" matches "example.com" and "a.example.com",
/// but NOT "badexample.com".
pub fn matchDomainSuffix(domain: []const u8, suffix: []const u8) bool {
    const norm_suffix = if (suffix.len > 0 and suffix[0] == '.') suffix[1..] else suffix;
    if (norm_suffix.len == 0) return true;
    if (domain.len < norm_suffix.len) return false;
    if (domain.len == norm_suffix.len) {
        return std.ascii.eqlIgnoreCase(domain, norm_suffix);
    }
    const prefix_len = domain.len - norm_suffix.len;
    if (domain[prefix_len - 1] != '.') return false;
    return std.ascii.eqlIgnoreCase(domain[prefix_len..], norm_suffix);
}

/// Matcher conditions for a single routing rule.
pub const Rule = struct {
    action: OutboundAction,
    exact_domain: ?[]const u8 = null,
    domain_suffix: ?[]const u8 = null,
    ipv4_cidr: ?Ipv4Cidr = null,
    ipv6_cidr: ?Ipv6Cidr = null,
    port: ?u16 = null,
    port_range: ?struct { min: u16, max: u16 } = null,

    /// Evaluates if the rule matches the given target endpoint.
    /// All specified conditions in this rule are combined via logical AND.
    pub fn matches(self: Rule, target: TargetEndpoint) bool {
        // Port matching
        if (self.port) |p| {
            if (target.port != p) return false;
        }
        if (self.port_range) |r| {
            if (target.port < r.min or target.port > r.max) return false;
        }

        // Address matching
        switch (target.address) {
            .domain => |d| {
                const domain_str = d.slice();
                // Domain cannot match IP CIDR without DNS resolution
                if (self.ipv4_cidr != null or self.ipv6_cidr != null) {
                    return false;
                }

                if (self.exact_domain) |ed| {
                    if (!std.ascii.eqlIgnoreCase(domain_str, ed)) return false;
                }
                if (self.domain_suffix) |ds| {
                    if (!matchDomainSuffix(domain_str, ds)) return false;
                }
            },
            .ipv4 => |ip| {
                // IPv4 cannot match domain rules or IPv6 rules
                if (self.exact_domain != null or self.domain_suffix != null or self.ipv6_cidr != null) {
                    return false;
                }
                if (self.ipv4_cidr) |cidr| {
                    if (!cidr.matches(ip)) return false;
                }
            },
            .ipv6 => |ip| {
                // IPv6 cannot match domain rules or IPv4 rules
                if (self.exact_domain != null or self.domain_suffix != null or self.ipv4_cidr != null) {
                    return false;
                }
                if (self.ipv6_cidr) |cidr| {
                    if (!cidr.matches(ip)) return false;
                }
            },
        }

        return true;
    }
};

/// Ordered routing table.
pub const Router = struct {
    rules: []const Rule,
    default_outbound: OutboundAction,
    owned_rules: ?[]Rule = null,
    arena: ?std.heap.ArenaAllocator = null,

    /// Initializes a Router using borrowed or static/comptime rules.
    /// Does not allocate memory; caller retains ownership of the slice and string data.
    pub fn initStatic(rules: []const Rule, default_outbound: OutboundAction) Router {
        return .{
            .rules = rules,
            .default_outbound = default_outbound,
            .owned_rules = null,
            .arena = null,
        };
    }

    /// Initializes a Router that owns its rules and allocated data.
    pub fn init(allocator: std.mem.Allocator, default_outbound: OutboundAction) Router {
        return .{
            .rules = &[_]Rule{},
            .default_outbound = default_outbound,
            .owned_rules = null,
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *Router) void {
        if (self.arena) |*a| {
            a.deinit();
            self.arena = null;
        }
        self.rules = &[_]Rule{};
        self.owned_rules = null;
    }

    /// Sets owned rules by copying the rule slice and any string literals into the router's arena.
    pub fn setRules(self: *Router, rules_slice: []const Rule) !void {
        if (self.arena == null) return error.NotAllocatedRouter;
        const arena_ptr = &self.arena.?;
        const arena_alloc = arena_ptr.allocator();

        const copy = try arena_alloc.alloc(Rule, rules_slice.len);
        for (rules_slice, 0..) |r, i| {
            var r_copy = r;
            if (r.exact_domain) |ed| {
                r_copy.exact_domain = try arena_alloc.dupe(u8, ed);
            }
            if (r.domain_suffix) |ds| {
                r_copy.domain_suffix = try arena_alloc.dupe(u8, ds);
            }
            copy[i] = r_copy;
        }
        self.owned_rules = copy;
        self.rules = copy;
    }

    /// Evaluates target endpoint against rules in order.
    /// The first matching rule determines the outbound action; otherwise returns default_outbound.
    pub fn route(self: Router, endpoint: TargetEndpoint) OutboundAction {
        for (self.rules) |rule| {
            if (rule.matches(endpoint)) {
                return rule.action;
            }
        }
        return self.default_outbound;
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

test "router: domain suffix label boundary matching" {
    // Exact domain
    try std.testing.expect(matchDomainSuffix("example.com", "example.com"));
    try std.testing.expect(matchDomainSuffix("EXAMPLE.COM", "example.com"));
    try std.testing.expect(matchDomainSuffix("example.com", "EXAMPLE.COM"));

    // Subdomains
    try std.testing.expect(matchDomainSuffix("a.example.com", "example.com"));
    try std.testing.expect(matchDomainSuffix("b.a.example.com", "example.com"));
    try std.testing.expect(matchDomainSuffix("a.b.c.example.com", ".example.com"));

    // Name boundary checks: must NOT match if dot is missing before suffix
    try std.testing.expect(!matchDomainSuffix("badexample.com", "example.com"));
    try std.testing.expect(!matchDomainSuffix("myexample.com", "example.com"));
    try std.testing.expect(!matchDomainSuffix("com", "example.com"));
    try std.testing.expect(!matchDomainSuffix("example.org", "example.com"));
}

test "router: IPv4 CIDR matching" {
    const cidr = try Ipv4Cidr.parse("192.168.1.0/24");
    try std.testing.expect(cidr.matches([_]u8{ 192, 168, 1, 1 }));
    try std.testing.expect(cidr.matches([_]u8{ 192, 168, 1, 254 }));
    try std.testing.expect(!cidr.matches([_]u8{ 192, 168, 2, 1 }));
    try std.testing.expect(!cidr.matches([_]u8{ 10, 0, 0, 1 }));

    const host_cidr = try Ipv4Cidr.parse("10.0.0.1/32");
    try std.testing.expect(host_cidr.matches([_]u8{ 10, 0, 0, 1 }));
    try std.testing.expect(!host_cidr.matches([_]u8{ 10, 0, 0, 2 }));

    const any_cidr = try Ipv4Cidr.parse("0.0.0.0/0");
    try std.testing.expect(any_cidr.matches([_]u8{ 1, 2, 3, 4 }));
    try std.testing.expect(any_cidr.matches([_]u8{ 127, 0, 0, 1 }));
}

test "router: IPv6 CIDR matching" {
    var prefix: [16]u8 = [_]u8{0} ** 16;
    prefix[0] = 0x20;
    prefix[1] = 0x01;
    prefix[2] = 0x0D;
    prefix[3] = 0xB8;
    const cidr = try Ipv6Cidr.init(prefix, 32);

    var matching_ip = prefix;
    matching_ip[15] = 1;
    try std.testing.expect(cidr.matches(matching_ip));

    var non_matching_ip = prefix;
    non_matching_ip[1] = 0x02;
    try std.testing.expect(!cidr.matches(non_matching_ip));
}

test "router: first matching rule determines outbound" {
    const rules = [_]Rule{
        // 1. Block specific internal domain
        .{
            .action = .block,
            .exact_domain = "block.internal.net",
        },
        // 2. Direct for all other internal.net subdomains on port 443
        .{
            .action = .direct,
            .domain_suffix = "internal.net",
            .port = 443,
        },
        // 3. Block any other internal.net
        .{
            .action = .block,
            .domain_suffix = "internal.net",
        },
        // 4. Direct for 127.0.0.0/8 on port 8080
        .{
            .action = .direct,
            .ipv4_cidr = try Ipv4Cidr.parse("127.0.0.0/8"),
            .port = 8080,
        },
    };

    const router = Router.initStatic(&rules, .direct);

    // Rule 1 matches first
    const ep1 = try TargetEndpoint.initDomain("block.internal.net", 443);
    try std.testing.expectEqual(OutboundAction.block, router.route(ep1));

    // Rule 2 matches
    const ep2 = try TargetEndpoint.initDomain("api.internal.net", 443);
    try std.testing.expectEqual(OutboundAction.direct, router.route(ep2));

    // Rule 3 matches (port 80 != 443)
    const ep3 = try TargetEndpoint.initDomain("api.internal.net", 80);
    try std.testing.expectEqual(OutboundAction.block, router.route(ep3));

    // Rule 4 matches
    const ep4 = TargetEndpoint.initIpv4([_]u8{ 127, 0, 0, 1 }, 8080);
    try std.testing.expectEqual(OutboundAction.direct, router.route(ep4));

    // Default outbound (.direct) for unmatched endpoint
    const ep_default = TargetEndpoint.initIpv4([_]u8{ 8, 8, 8, 8 }, 53);
    try std.testing.expectEqual(OutboundAction.direct, router.route(ep_default));
}

test "router: AND conjunction of rule conditions" {
    const rules = [_]Rule{
        .{
            .action = .block,
            .domain_suffix = "adserver.com",
            .port = 80,
        },
    };
    const router = Router.initStatic(&rules, .direct);

    // Matches both domain suffix AND port 80 -> block
    const ep_blocked = try TargetEndpoint.initDomain("track.adserver.com", 80);
    try std.testing.expectEqual(OutboundAction.block, router.route(ep_blocked));

    // Same domain but port 443 -> does NOT match rule, falls back to default (.direct)
    const ep_allowed = try TargetEndpoint.initDomain("track.adserver.com", 443);
    try std.testing.expectEqual(OutboundAction.direct, router.route(ep_allowed));
}

test "router: owned rules arena lifecycle" {
    var router = Router.init(std.testing.allocator, .block);
    defer router.deinit();

    const rules = [_]Rule{
        .{
            .action = .direct,
            .exact_domain = "allowed.com",
        },
    };
    try router.setRules(&rules);

    const ep = try TargetEndpoint.initDomain("allowed.com", 443);
    try std.testing.expectEqual(OutboundAction.direct, router.route(ep));

    const ep_unmatched = try TargetEndpoint.initDomain("denied.com", 443);
    try std.testing.expectEqual(OutboundAction.block, router.route(ep_unmatched));
}

test "review: owned router allocation failures clean up" {
    const routerOOM = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var router = Router.init(allocator, .block);
            defer router.deinit();
            try router.setRules(&.{.{
                .action = .direct,
                .exact_domain = "example.com",
                .domain_suffix = "example.com",
                .port = 443,
            }});
            try std.testing.expectEqual(OutboundAction.direct, router.route(try TargetEndpoint.initDomain("example.com", 443)));
        }
    }.run;
    try std.testing.checkAllAllocationFailures(std.testing.allocator, routerOOM, .{});
}
