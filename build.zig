const std = @import("std");

const version = @import("src/version.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addSharedLibrary(.{
        .name = "srb-id-pkcs11",
        .root_source_file = b.path("src/p11_general.zig"),
        .target = target,
        .optimize = optimize,
        .version = null,
    });

    switch (target.result.os.tag) {
        std.Target.Os.Tag.windows => {
            lib.addIncludePath(b.path("include"));
            lib.addIncludePath(.{ .cwd_relative = "vcpkg/packages/openssl_x64-windows/include/openssl" });
            lib.addLibraryPath(.{ .cwd_relative = "vcpkg/packages/openssl_x64-windows/bin" });
            lib.linkSystemLibrary("libssl");
            lib.linkSystemLibrary("pcsclite");
        },
        std.Target.Os.Tag.macos => {
            lib.addIncludePath(b.path("include"));
            lib.addIncludePath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/include" });
            lib.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/lib" });
            lib.linkSystemLibrary("ssl");
            lib.linkSystemLibrary("crypto");
            lib.linkFramework("PCSC");
        },
        else => {
            lib.addIncludePath(b.path("include"));
            lib.addIncludePath(.{ .cwd_relative = "/usr/include/PCSC/" });
            lib.linkSystemLibrary("pcsclite");
            lib.linkSystemLibrary("openssl");
        },
    }

    b.installArtifact(lib);

    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/p11_general.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}
