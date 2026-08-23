//! Thin Rust proxy over the libitb shared library's Triple Pipeline
//! surface.
//!
//! The crate wraps the `ITB_Triple_*` C ABI exported by `cmd/cshared`
//! (libitb.so / .dylib / .dll) through `libloading` — runtime FFI, no
//! compile-time link, no C compiler at install time. Every hash-name /
//! MAC-name / cipher-name / profile-name is an opaque string passed
//! through to Go for validation; the binding carries no ITB
//! construction logic of its own.
//!
//! ```no_run
//! use itb::{OptsBuilder, Pipeline};
//!
//! let opts = OptsBuilder::new();
//! let sender = Pipeline::init("singlemsg-triple-mac-v1", &opts)?;
//! let receiver = Pipeline::open("singlemsg-triple-mac-v1", sender.blob(), &opts, None)?;
//! let wire = sender.encrypt_message(b"hello")?;
//! assert_eq!(receiver.decrypt_message(&wire)?, b"hello");
//! # Ok::<(), itb::ItbError>(())
//! ```

mod error;
mod ffi;
mod opts;
mod pipeline;
mod register;
mod runtime;
mod status;
mod stream;

pub use error::{ItbError, ItbResult};
pub use opts::OptsBuilder;
pub use pipeline::Pipeline;
pub use register::register_profile;
pub use runtime::{set_gc_percent, set_memory_limit, version};
pub use status::ItbStatus;
pub use stream::{DecryptStream, EncryptStream};
