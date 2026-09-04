// Session persistence surface: save / load, saveF / loadF, inspect,
// lookup / profiles / register round trip, maxWorkers clamping.

package dev.everanium.itb

import java.nio.file.Files

import scala.util.Using

class PersistSuite extends ItbSuite:

  private val plain = "persisted session payload".getBytes("UTF-8")

  test("save then load round trip") {
    Using.resource(ok(Pipeline.init("singlemsg-triple-mac-v1"))) { sender =>
      val blob = ok(sender.save())
      assert(blob.nonEmpty)
      assert(ok(sender.save()).sameElements(blob))
      Using.resource(ok(Pipeline.load(blob))) { receiver =>
        assert(ok(receiver.save()).sameElements(blob))
        val wire = ok(sender.encryptMessage(plain))
        assert(ok(receiver.decryptMessage(wire)).sameElements(plain))
      }
    }
  }

  test("saveF then loadF round trip") {
    val dir = Files.createTempDirectory("itb-scala-")
    val file = dir.resolve("session.blob")
    try
      Using.resource(ok(Pipeline.init("streaming-aead-triple-mac-v1"))) { sender =>
        ok(sender.saveF(file.toString))
        val saved = ok(sender.save())
        assert(Files.readAllBytes(file).sameElements(saved))
        Using.resource(ok(Pipeline.loadF(file.toString))) { receiver =>
          val wire = ok(sender.encryptStreamOneShot(plain))
          assert(ok(receiver.decryptStreamOneShot(wire)).sameElements(plain))
        }
      }
    finally
      Files.deleteIfExists(file)
      Files.deleteIfExists(dir)
  }

  test("load with master override") {
    val perm = Array.fill[Byte](32)(0x33)
    val wrap = Array.fill[Byte](32)(0x44)
    Using.resource(ok(Pipeline.init("singlemsg-triple-mac-v1"))) { sender =>
      val blob = ok(sender.save())
      val rotated = ok(sender.rekey(perm, wrap))
      assert(!rotated.sameElements(blob))
      assert(ok(sender.save()).sameElements(rotated))
      Using.resource(ok(Pipeline.loadWithMasters(blob, perm, wrap))) { receiver =>
        val wire = ok(sender.encryptMessage(plain))
        assert(ok(receiver.decryptMessage(wire)).sameElements(plain))
      }
    }
  }

  test("inspect reads the embedded record") {
    Using.resource(ok(Pipeline.init("streaming-aead-triple-mac-v1"))) { pipe =>
      val prof = ok(Pipeline.inspect(ok(pipe.save())))
      assertEquals(prof.name(), "streaming-aead-triple-mac-v1")
      assertEquals(prof.mode(), "streaming-aead")
      assertEquals(prof.width(), 512)
      assertEquals(ok(Pipeline.lookup("streaming-aead-triple-mac-v1")), prof)
    }
  }

  test("profiles lists the catalogue") {
    val names = ok(Pipeline.profiles())
    assert(names.contains("singlemsg-triple-mac-v1"))
    assert(names.contains("streaming-aead-triple-mac-v1"))
  }

  test("register copy of shipped profile") {
    val copy = ok(Pipeline.lookup("singlemsg-triple-nomac-v1")).name("")
    ok(Pipeline.register("scala-binding-test-copy", copy))
    val back = ok(Pipeline.lookup("scala-binding-test-copy"))
    assertEquals(back.name(), "scala-binding-test-copy")
    assertEquals(back.mode(), copy.mode())
    assert(ok(Pipeline.profiles()).contains("scala-binding-test-copy"))
    Using.resource(ok(Pipeline.init("scala-binding-test-copy"))) { sender =>
      Using.resource(ok(Pipeline.load(ok(sender.save())))) { receiver =>
        val wire = ok(sender.encryptMessage(plain))
        assert(ok(receiver.decryptMessage(wire)).sameElements(plain))
      }
    }
  }

  test("maxWorkers clamps") {
    val opts = Opts.empty.withMaxWorkers(-1)
    Using.resource(ok(Pipeline.init("singlemsg-triple-mac-v1", opts))) { pipe =>
      ok(pipe.maxWorkers(2))
      ok(pipe.maxWorkers(-1))
      ok(pipe.maxWorkers(1000))
      val wire = ok(pipe.encryptMessage(plain))
      assert(ok(pipe.decryptMessage(wire)).sameElements(plain))
    }
  }
