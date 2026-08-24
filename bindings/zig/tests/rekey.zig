//! Init → rekey → open receiver with the rotated blob → round trip.

const std = @import("std");
const itb = @import("itb");

test "rekey refreshes the blob and the pair still round-trips" {
    const gpa = std.testing.allocator;

    var sender = try itb.Pipeline.init(gpa, "singlemsg-triple-mac-v1", null);
    defer sender.deinit();

    const before = try gpa.dupe(u8, sender.blob());
    defer gpa.free(before);

    const perm = [_]u8{0x11} ** 32;
    const wrap = [_]u8{0x22} ** 32;
    try sender.rekey(&perm, &wrap);
    try std.testing.expect(!std.mem.eql(u8, before, sender.blob()));

    var receiver = try itb.Pipeline.open(
        gpa,
        "singlemsg-triple-mac-v1",
        sender.blob(),
        null,
        null,
    );
    defer receiver.deinit();

    const plain = "post-rekey payload";
    const wire = try sender.encryptMessage(plain);
    defer gpa.free(wire);
    const back = try receiver.decryptMessage(wire);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, plain, back);
}
