const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    if (target.result.os.tag != .macos) {
        std.log.err("Virm currently requires the macOS kqueue backend; requested OS: {s}", .{@tagName(target.result.os.tag)});
        std.process.exit(1);
    }

    const core_module = b.addModule("virm", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const cli_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "virm", .module = core_module }},
    });

    const exe = b.addExecutable(.{
        .name = "virm",
        .root_module = cli_module,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    const run_step = b.step("run", "Run the SOCKS5 proxy server");
    run_step.dependOn(&run_cmd.step);

    const core_tests = b.addTest(.{ .root_module = core_module });
    const cli_tests = b.addTest(.{ .root_module = cli_module });
    const run_core_tests = b.addRunArtifact(core_tests);
    const run_cli_tests = b.addRunArtifact(cli_tests);

    const test_step = b.step("test", "Run core and CLI tests");
    test_step.dependOn(&run_core_tests.step);
    test_step.dependOn(&run_cli_tests.step);
}
