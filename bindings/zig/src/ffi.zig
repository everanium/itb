//! Centralised C import of the ITB C binding's public header.
//!
//! Every other module reaches the C ABI exclusively through `ffi.c`;
//! no second `@cImport` site exists in the binding. The include path
//! for `itb.h` and the link inputs (`libitb_c.a` + `-litb` with an
//! embedded RPATH into `dist/`) are wired by `build.zig`.

pub const c = @cImport({
    @cInclude("itb.h");
});
