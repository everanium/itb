//! encryptStreamPump throughput vs plaintext size (streaming
//! Non-AEAD profile) at 1 MiB / 16 MiB / 64 MiB.

const std = @import("std");
const itb = @import("itb");
const util = @import("bench_util.zig");

const Ctx = struct {
    pipe: *const itb.Pipeline,
    plain: []const u8,
};

fn runStreamPump(ctx: *const Ctx) !void {
    const wire = try ctx.pipe.encryptStreamPump(ctx.plain);
    ctx.pipe.allocator.free(wire);
}

pub fn main(init: std.process.Init) !void {
    // Bench-scale allocation churn leaks Go scratch heap unboundedly
    // without a soft memory cap + aggressive GC; the return values
    // report the previous settings, not an error.
    _ = itb.setMemoryLimit(512 << 20); // 512 MiB soft cap
    _ = itb.setGcPercent(20); // aggressive GC

    const gpa = init.gpa;
    const arena = init.arena.allocator();
    const env = init.environ_map;

    const opts = try util.buildOpts(arena, env);
    defer opts.deinit();
    var pipe = try itb.Pipeline.init(
        gpa,
        try util.profileName(arena, env, "streaming-noaead-triple-v1"),
        opts,
    );
    defer pipe.deinit();

    try util.header(init.io);
    const budget = util.minSeconds(env);
    const sizes = [_]usize{ 1 << 20, 16 << 20, 64 << 20 };
    for (sizes) |size| {
        const plain = try gpa.alloc(u8, size);
        defer gpa.free(plain);
        try util.randomFill(plain); // not in the timing loop
        const ctx = Ctx{ .pipe = &pipe, .plain = plain };
        try util.benchCase(init.io, budget, "stream_pump", size, &ctx, runStreamPump);
    }
}
