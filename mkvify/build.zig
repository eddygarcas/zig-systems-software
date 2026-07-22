const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // FFmpeg's C libraries. On Debian/Ubuntu the headers sit under an
    // architecture triple, so pick that up when it exists.
    linkFfmpeg(mod);

    const exe = b.addExecutable(.{
        .name = "mkvify",
        .root_module = mod,
    });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    run.step.dependOn(b.getInstallStep());
    if (b.args) |args| run.addArgs(args);
    b.step("run", "Build and run mkvify").dependOn(&run.step);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    linkFfmpeg(test_mod);

    const tests = b.addTest(.{ .root_module = test_mod });
    const run_tests = b.addRunArtifact(tests);
    b.step("test", "Run the decision-engine tests").dependOn(&run_tests.step);
}

fn linkFfmpeg(mod: *std.Build.Module) void {
    // Use the pkg-config names: this resolves the include paths too, which
    // matters because distributions disagree about where the headers live
    // (Arch puts them in /usr/include, Debian under an arch triple).
    mod.linkSystemLibrary("libavformat", .{});
    mod.linkSystemLibrary("libavcodec", .{});
    mod.linkSystemLibrary("libavutil", .{});
}
