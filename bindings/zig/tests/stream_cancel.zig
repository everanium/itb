//! Deiniting an encrypt session mid-flight (no `end`) releases
//! resources cleanly and leaves the Pipeline usable. The process
//! exiting without hang or crash — and the leak-checking test
//! allocator staying clean — is the assertion.

const std = @import("std");
const itb = @import("itb");

test "mid-flight cancel leaves the Pipeline usable" {
    const gpa = std.testing.allocator;

    var sender = try itb.Pipeline.init(gpa, "streaming-aead-triple-mac-v1", null);
    defer sender.deinit();

    const chunk = try gpa.alloc(u8, 100000);
    defer gpa.free(chunk);
    var x: u64 = 0xA5A5A5A5;
    for (chunk) |*b| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        b.* = @truncate(x);
    }

    var sess = try sender.encryptStream();
    try sess.write(chunk);
    // Deinited here without end() — the session is cancelled.
    sess.deinit();

    // The Pipeline stays usable after the cancelled session.
    var receiver = try itb.Pipeline.open(
        gpa,
        "streaming-aead-triple-mac-v1",
        sender.blob(),
        null,
        null,
    );
    defer receiver.deinit();

    const plain = "after cancel";
    const wire = try sender.encryptMessage(plain);
    defer gpa.free(wire);
    const back = try receiver.decryptMessage(wire);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, plain, back);
}
