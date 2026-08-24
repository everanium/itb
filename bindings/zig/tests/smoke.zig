//! Init → blob → Open → encryptMessage → decryptMessage round trip.

const std = @import("std");
const itb = @import("itb");

test "smoke round trip" {
    const gpa = std.testing.allocator;

    var sender = try itb.Pipeline.init(gpa, "singlemsg-triple-mac-v1", null);
    defer sender.deinit();
    try std.testing.expect(sender.blob().len > 0);

    var receiver = try itb.Pipeline.open(
        gpa,
        "singlemsg-triple-mac-v1",
        sender.blob(),
        null,
        null,
    );
    defer receiver.deinit();

    const plain = "smoke round-trip payload";

    const wire = try sender.encryptMessage(plain);
    defer gpa.free(wire);
    try std.testing.expect(wire.len != plain.len or !std.mem.eql(u8, wire, plain));

    const back = try receiver.decryptMessage(wire);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, plain, back);
}
