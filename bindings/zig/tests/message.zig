//! Single Message round trip across every shipped cipher-bearing
//! profile at small (4 KiB) and medium (256 KiB) payloads.

const std = @import("std");
const itb = @import("itb");

/// Deterministic non-trivial payload (xorshift fill). Caller frees.
fn payload(gpa: std.mem.Allocator, n: usize, seed: u64) ![]u8 {
    const buf = try gpa.alloc(u8, n);
    var x = seed | 1;
    for (buf) |*b| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        b.* = @truncate(x);
    }
    return buf;
}

fn roundTrip(profile: [:0]const u8, size: usize) !void {
    const gpa = std.testing.allocator;

    var sender = try itb.Pipeline.init(gpa, profile, null);
    defer sender.deinit();
    var receiver = try itb.Pipeline.open(gpa, profile, sender.blob(), null, null);
    defer receiver.deinit();

    const plain = try payload(gpa, size, size);
    defer gpa.free(plain);

    const wire = try sender.encryptMessage(plain);
    defer gpa.free(wire);
    const back = try receiver.decryptMessage(wire);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, plain, back);
}

test "message round trip per profile and size" {
    const profiles = [_][:0]const u8{
        "streaming-aead-triple-mac-v1",
        "streaming-noaead-triple-v1",
        "singlemsg-triple-mac-v1",
        "singlemsg-triple-nomac-v1",
        "streaming-aead-triple-mac-mixed-v1",
        "streaming-noaead-triple-mixed-v1",
        "singlemsg-triple-mac-mixed-v1",
        "singlemsg-triple-nomac-mixed-v1",
    };
    const sizes = [_]usize{ 4 * 1024, 256 * 1024 };
    for (profiles) |profile| {
        for (sizes) |size| {
            try roundTrip(profile, size);
        }
    }
}

test "empty plaintext round trips" {
    const gpa = std.testing.allocator;

    var sender = try itb.Pipeline.init(gpa, "singlemsg-triple-mac-v1", null);
    defer sender.deinit();
    var receiver = try itb.Pipeline.open(
        gpa,
        "singlemsg-triple-mac-v1",
        sender.blob(),
        null,
        null,
    );
    defer receiver.deinit();

    const wire = try sender.encryptMessage(&.{});
    defer gpa.free(wire);
    try std.testing.expect(wire.len > 0);

    const back = try receiver.decryptMessage(wire);
    defer gpa.free(back);
    try std.testing.expectEqual(@as(usize, 0), back.len);
}
