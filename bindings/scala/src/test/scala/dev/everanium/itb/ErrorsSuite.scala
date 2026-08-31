// Error-mapping surface: opaque-string relay, closed Pipeline,
// duplicate profile registration (with an 8-entry innerHashes
// constellation).

package dev.everanium.itb

import scala.util.Using

class ErrorsSuite extends ItbSuite:

  test("unknown profile is BadInput with diagnostic") {
    val e = err(Pipeline.init("no-such-profile"))
    assertEquals(e.status, Status.BadInput)
    assert(e.getMessage.nonEmpty)
  }

  test("unknown opts key is BadInput") {
    // Typoed key (lowercase s) — Go rejects unknown keys.
    val opts = Opts.empty.withRaw("chunksize", "4096")
    val e = err(Pipeline.init("singlemsg-triple-mac-v1", opts))
    assertEquals(e.status, Status.BadInput)
  }

  test("closed pipeline reports TripleClosed") {
    Using.resource(ok(Pipeline.init("singlemsg-triple-mac-v1"))) { pipe =>
      ok(pipe.closeSession())
      ok(pipe.closeSession()) // idempotent
      val e = err(pipe.encryptMessage("payload".getBytes("UTF-8")))
      assertEquals(e.status, Status.TripleClosed)
    }
  }

  test("register profile mixed then duplicate") {
    // 8-entry width-256 innerHashes constellation, layers off.
    val opts = Opts.empty
      .withRaw("mode", "singlemsg-nomac")
      .withRaw("width", "256")
      .withRaw(
        "innerHashes",
        "blake3,blake2s,areion256,blake2b256,chacha20,blake3,blake2s,areion256"
      )
      .withRaw("keyBits", "1024")
      .withRaw("parallaxOn", "false")
      .withRaw("wrapperOn", "false")
    ok(Pipeline.registerProfile("scala-binding-test-mixed", opts))

    // The registered profile round-trips.
    Using.resource(ok(Pipeline.init("scala-binding-test-mixed"))) { sender =>
      Using.resource(ok(Pipeline.open("scala-binding-test-mixed", sender.blob))) { receiver =>
        val plain = "custom profile".getBytes("UTF-8")
        val wire = ok(sender.encryptMessage(plain))
        assert(ok(receiver.decryptMessage(wire)).sameElements(plain))
      }
    }

    // Duplicate name is a distinct status.
    val e = err(Pipeline.registerProfile("scala-binding-test-mixed", opts))
    assertEquals(e.status, Status.ProfileExists)
  }

  test("opaque primitive name relay") {
    // An unknown inner-hash name is relayed to Go and rejected there
    // — the binding performs no name validation of its own.
    val opts = Opts.empty.withInnerHash("no-such-hash")
    val e = err(Pipeline.init("singlemsg-triple-mac-v1", opts))
    assert(e.status != Status.Ok)
  }

  test("per-call innerHashes override round-trips") {
    // The single-primitive width-512 base profile takes an 8-slot
    // per-call MixedHashes override (Go-side Opts.MixedHashes, wired
    // through the innerHashes= opts key). Round-trip proves the typed
    // helper's comma-join lands in the Go parser correctly.
    val senderOpts = Opts.empty.withInnerHashes(
      "areion512", "blake2b512", "areion512", "blake2b512",
      "areion512", "blake2b512", "areion512", "blake2b512",
    )
    val receiverOpts = Opts.empty.withInnerHashes(
      "areion512", "blake2b512", "areion512", "blake2b512",
      "areion512", "blake2b512", "areion512", "blake2b512",
    )
    Using.resource(ok(Pipeline.init("singlemsg-triple-mac-v1", senderOpts))) { sender =>
      Using.resource(ok(Pipeline.open("singlemsg-triple-mac-v1", sender.blob, receiverOpts))) {
        receiver =>
          val plain = "per-call inner-hashes override round-trip payload".getBytes("UTF-8")
          val wire = ok(sender.encryptMessage(plain))
          assert(ok(receiver.decryptMessage(wire)).sameElements(plain))
      }
    }
  }
