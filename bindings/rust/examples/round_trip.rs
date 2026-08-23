//! Minimal sender / receiver round trip over the Triple Pipeline.
//!
//! Run with `cargo run --example round_trip --release` (after
//! `./build.sh`).

use itb::{OptsBuilder, Pipeline};

fn main() -> Result<(), itb::ItbError> {
    let opts = OptsBuilder::new();

    // Sender: fresh session against a shipped profile; the blob is
    // the session bundle the receiver needs.
    let sender = Pipeline::init("singlemsg-triple-mac-v1", &opts)?;

    // Receiver: reconstructed from the blob.
    let receiver = Pipeline::open("singlemsg-triple-mac-v1", sender.blob(), &opts, None)?;

    let plaintext = b"any text or binary data - including 0x00 bytes";
    let wire = sender.encrypt_message(plaintext)?;
    let recovered = receiver.decrypt_message(&wire)?;

    assert_eq!(recovered, plaintext);
    println!(
        "ok: {} plaintext bytes, {} wire bytes",
        plaintext.len(),
        wire.len()
    );
    Ok(())
}
