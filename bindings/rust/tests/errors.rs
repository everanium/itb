//! Error-mapping surface: opaque-string relay, closed Pipeline,
//! duplicate profile registration (with an 8-entry `innerHashes`
//! constellation).

use itb::{ItbStatus, OptsBuilder, Pipeline, register_profile};

#[test]
fn unknown_profile_is_bad_input_with_diagnostic() {
    let err = Pipeline::init("no-such-profile", &OptsBuilder::new()).unwrap_err();
    assert_eq!(err.status(), Some(ItbStatus::BadInput));
    assert!(!err.to_string().is_empty());
}

#[test]
fn unknown_opts_key_is_bad_input() {
    // Typoed key (lowercase s) — Go rejects unknown keys.
    let opts = OptsBuilder::new().with_raw("chunksize", "4096");
    let err = Pipeline::init("singlemsg-triple-mac-v1", &opts).unwrap_err();
    assert_eq!(err.status(), Some(ItbStatus::BadInput));
}

#[test]
fn closed_pipeline_reports_triple_closed() {
    let mut p = Pipeline::init("singlemsg-triple-mac-v1", &OptsBuilder::new()).unwrap();
    p.close().unwrap();
    p.close().unwrap(); // idempotent
    let err = p.encrypt_message(b"payload").unwrap_err();
    assert_eq!(err.status(), Some(ItbStatus::TripleClosed));
}

#[test]
fn register_profile_mixed_then_duplicate() {
    // 8-entry width-256 innerHashes constellation, layers off.
    let opts = OptsBuilder::new()
        .with_raw("mode", "singlemsg-nomac")
        .with_raw("width", "256")
        .with_raw(
            "innerHashes",
            "blake3,blake2s,areion256,blake2b256,chacha20,blake3,blake2s,areion256",
        )
        .with_raw("keyBits", "1024")
        .with_raw("parallaxOn", "false")
        .with_raw("wrapperOn", "false");
    register_profile("rust-binding-test-mixed", &opts).unwrap();

    // The registered profile round-trips.
    let sender = Pipeline::init("rust-binding-test-mixed", &OptsBuilder::new()).unwrap();
    let receiver = Pipeline::open(
        "rust-binding-test-mixed",
        sender.blob(),
        &OptsBuilder::new(),
        None,
    )
    .unwrap();
    let wire = sender.encrypt_message(b"custom profile").unwrap();
    assert_eq!(receiver.decrypt_message(&wire).unwrap(), b"custom profile");

    // Duplicate name is a distinct status.
    let err = register_profile("rust-binding-test-mixed", &opts).unwrap_err();
    assert_eq!(err.status(), Some(ItbStatus::ProfileExists));
}

#[test]
fn opaque_primitive_name_relay() {
    // An unknown inner-hash name is relayed to Go and rejected there —
    // the binding performs no name validation of its own.
    let opts = OptsBuilder::new().with_inner_hash("no-such-hash");
    let err = Pipeline::init("singlemsg-triple-mac-v1", &opts).unwrap_err();
    assert!(err.status().is_some());
    assert_ne!(err.status(), Some(ItbStatus::Ok));
}

#[test]
fn per_call_inner_hashes_override_round_trips() {
    // The single-primitive width-512 base profile takes an 8-slot
    // per-call MixedHashes override (Go-side Opts.MixedHashes, wired
    // through the innerHashes= opts key). Round-trip proves the typed
    // helper's comma-join lands in the Go parser correctly.
    let mix = [
        "areion512", "blake2b512", "areion512", "blake2b512",
        "areion512", "blake2b512", "areion512", "blake2b512",
    ];
    let sender_opts = OptsBuilder::new().with_inner_hashes(&mix);
    let sender = Pipeline::init("singlemsg-triple-mac-v1", &sender_opts).unwrap();
    let receiver_opts = OptsBuilder::new().with_inner_hashes(&mix);
    let receiver = Pipeline::open(
        "singlemsg-triple-mac-v1",
        sender.blob(),
        &receiver_opts,
        None,
    )
    .unwrap();
    let plain = b"per-call inner-hashes override round-trip payload";
    let wire = sender.encrypt_message(plain).unwrap();
    assert_eq!(receiver.decrypt_message(&wire).unwrap(), plain);
}
