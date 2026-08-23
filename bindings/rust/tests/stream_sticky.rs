//! A decrypt session fed a tampered wire fails with a sticky error.

use itb::{OptsBuilder, Pipeline};

#[test]
fn tampered_wire_sticky_failure() {
    let opts = OptsBuilder::new();
    let sender = Pipeline::init("streaming-aead-triple-mac-v1", &opts).unwrap();
    let receiver =
        Pipeline::open("streaming-aead-triple-mac-v1", sender.blob(), &opts, None).unwrap();

    let plain: Vec<u8> = (0..65_536).map(|i| (i % 227) as u8).collect();
    let mut wire = sender.encrypt_stream_one_shot(&plain).unwrap();

    // Flip one bit inside the wire body.
    let idx = wire.len() * 3 / 4;
    wire[idx] ^= 0x01;

    let mut sess = receiver.decrypt_stream().unwrap();
    // The failure may surface on write (chain already failed) or on a
    // later read — either way a read must eventually report it.
    let _ = sess.write(&wire);
    let _ = sess.end();

    let mut buf = [0u8; 4096];
    let mut first_err = None;
    loop {
        match sess.read(&mut buf) {
            Ok((_, true)) => break,
            Ok((_, false)) => continue,
            Err(e) => {
                first_err = Some(e);
                break;
            }
        }
    }
    let first = first_err.expect("tampered wire must fail authentication / decryption");
    let first_status = first.status().expect("error carries a status code");

    // Sticky: a subsequent read reports the same status.
    let again = sess.read(&mut buf).unwrap_err();
    assert_eq!(again.status(), Some(first_status));
}
