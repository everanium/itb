//! Error-mapping surface: opaque-string relay, opts-builder
//! rendering, profile registration, duplicate-profile status.

const std = @import("std");
const itb = @import("itb");

test "unknown profile is rejected Go-side" {
    const gpa = std.testing.allocator;
    try std.testing.expectError(
        error.BadInput,
        itb.Pipeline.init(gpa, "no-such-profile", null),
    );
    try std.testing.expect(itb.lastError().len > 0);
}

test "unknown opts key is rejected Go-side" {
    const gpa = std.testing.allocator;
    const opts = try itb.Opts.init();
    defer opts.deinit();
    // Typoed lowercase s — the builder itself performs no validation.
    try opts.set("chunksize", "4096");
    try std.testing.expectError(
        error.BadInput,
        itb.Pipeline.init(gpa, "singlemsg-triple-mac-v1", opts),
    );
}

test "unknown inner hash name is relayed and rejected" {
    const gpa = std.testing.allocator;
    const opts = try itb.Opts.init();
    defer opts.deinit();
    try opts.set("innerHash", "no-such-hash");
    const result = itb.Pipeline.init(gpa, "singlemsg-triple-mac-v1", opts);
    try std.testing.expect(if (result) |_| false else |_| true);
}

test "opts builder renders insertion order and percent-encodes" {
    const opts = try itb.Opts.init();
    defer opts.deinit();
    try std.testing.expectEqualStrings("", opts.query());
    try opts.set("chunkSize", "4096");
    try opts.set("parallaxPalette", "aescmac,chacha20,blake3");
    try std.testing.expectEqualStrings(
        "chunkSize=4096&parallaxPalette=aescmac,chacha20,blake3",
        opts.query(),
    );

    const enc = try itb.Opts.init();
    defer enc.deinit();
    try enc.set("mode", "a b&c=d%");
    try std.testing.expectEqualStrings("mode=a%20b%26c%3Dd%25", enc.query());
}

test "register profile, use it, duplicate is ProfileExists" {
    const gpa = std.testing.allocator;

    const reg = try itb.Opts.init();
    defer reg.deinit();
    try reg.set("mode", "singlemsg-nomac");
    try reg.set("width", "256");
    try reg.set("innerHashes", "blake3,blake2s,areion256,blake2b256," ++
        "chacha20,blake3,blake2s,areion256");
    try reg.set("keyBits", "1024");
    try reg.set("parallaxOn", "false");
    try reg.set("wrapperOn", "false");
    try itb.registerProfile("zig-binding-test-mixed", reg);

    var sender = try itb.Pipeline.init(gpa, "zig-binding-test-mixed", null);
    defer sender.deinit();
    var receiver = try itb.Pipeline.open(
        gpa,
        "zig-binding-test-mixed",
        sender.blob(),
        null,
        null,
    );
    defer receiver.deinit();

    const plain = "custom profile";
    const wire = try sender.encryptMessage(plain);
    defer gpa.free(wire);
    const back = try receiver.decryptMessage(wire);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, plain, back);

    try std.testing.expectError(
        error.ProfileExists,
        itb.registerProfile("zig-binding-test-mixed", reg),
    );
}
