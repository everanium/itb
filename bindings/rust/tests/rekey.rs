//! Init → Rekey → Open receiver with the rotated blob → round trip.

use itb::{OptsBuilder, Pipeline};

#[test]
fn rekey_round_trip() {
    let opts = OptsBuilder::new();
    let mut sender = Pipeline::init("singlemsg-triple-mac-v1", &opts).unwrap();
    let blob_before = sender.blob().to_vec();

    let perm = [0x11u8; 32];
    let wrap = [0x22u8; 32];
    sender.rekey(&perm, &wrap).unwrap();
    assert_ne!(
        sender.blob(),
        &blob_before[..],
        "rekey must refresh the blob"
    );

    let receiver = Pipeline::open("singlemsg-triple-mac-v1", sender.blob(), &opts, None).unwrap();
    let plain = b"post-rekey payload".to_vec();
    let wire = sender.encrypt_message(&plain).unwrap();
    assert_eq!(receiver.decrypt_message(&wire).unwrap(), plain);
}
