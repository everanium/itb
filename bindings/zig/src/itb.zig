//! Thin Zig proxy over the ITB C binding (`bindings/c`), which in
//! turn wraps the libitb shared library's Triple Pipeline surface.
//!
//! The module `@cImport`s the C binding's public `itb.h` and links
//! `libitb_c.a` + `libitb.so` at compile time — no runtime symbol
//! loading. Every hash-name / MAC-name / cipher-name / profile-name
//! is an opaque string passed through to Go for validation; the
//! binding carries no ITB construction logic. Buffer sizing and the
//! BufferTooSmall retry-once dance live in the C layer.
//!
//!     const itb = @import("itb");
//!
//!     var sender = try itb.Pipeline.init(allocator, "singlemsg-triple-mac-v1", null);
//!     defer sender.deinit();
//!     var receiver = try itb.Pipeline.open(
//!         allocator, "singlemsg-triple-mac-v1", sender.blob(), null, null);
//!     defer receiver.deinit();
//!
//!     const wire = try sender.encryptMessage("hello");
//!     defer allocator.free(wire);
//!     const plain = try receiver.decryptMessage(wire);
//!     defer allocator.free(plain);

/// Zig binding version. Tracks the Zig wrapper; call `version` for
/// the underlying libitb library version.
pub const binding_version: [:0]const u8 = "0.3.5";

pub const ffi = @import("ffi.zig");

pub const Status = @import("status.zig").Status;

const error_mod = @import("error.zig");
pub const Error = error_mod.Error;
pub const check = error_mod.check;
pub const lastError = error_mod.lastError;

pub const Opts = @import("opts.zig").Opts;

const pipeline_mod = @import("pipeline.zig");
pub const Pipeline = pipeline_mod.Pipeline;
pub const Masters = pipeline_mod.Masters;

const stream_mod = @import("stream.zig");
pub const EncryptStream = stream_mod.EncryptStream;
pub const DecryptStream = stream_mod.DecryptStream;
pub const ReadResult = stream_mod.ReadResult;

const runtime_mod = @import("runtime.zig");
pub const registerProfile = runtime_mod.registerProfile;
pub const version = runtime_mod.version;
pub const setMemoryLimit = runtime_mod.setMemoryLimit;
pub const setGcPercent = runtime_mod.setGcPercent;
pub const hashCount = runtime_mod.hashCount;
pub const hashName = runtime_mod.hashName;
pub const hashWidth = runtime_mod.hashWidth;
