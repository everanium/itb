// Init -> rekey -> open receiver with the rotated blob -> round
// trip.

package dev.everanium.itb

import scala.util.Using

class RekeySuite extends ItbSuite:

  test("rekey round trip") {
    Using.resource(ok(Pipeline.init("singlemsg-triple-mac-v1"))) { sender =>
      val blobBefore = sender.blob.clone()

      val perm = Array.fill(32)(0x11.toByte)
      val wrap = Array.fill(32)(0x22.toByte)
      ok(sender.rekey(perm, wrap))
      assert(!sender.blob.sameElements(blobBefore))

      Using.resource(ok(Pipeline.open("singlemsg-triple-mac-v1", sender.blob))) { receiver =>
        val plain = "post-rekey payload".getBytes("UTF-8")
        val wire = ok(sender.encryptMessage(plain))
        assert(ok(receiver.decryptMessage(wire)).sameElements(plain))
      }
    }
  }
