// Init -> Rekey -> load receiver from the rotated blob -> round trip.

package com.everanium.itb.kotlin

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse

class RekeyTest {

    @Test
    fun rekeyRoundTrip() {
        Pipeline.init("singlemsg-triple-mac-v1").use { sender ->
            val blobBefore = sender.save()

            val perm = ByteArray(32) { 0x11 }
            val wrap = ByteArray(32) { 0x22 }
            sender.rekey(perm, wrap)
            assertFalse(sender.save().contentEquals(blobBefore))

            Pipeline.load(sender.save()).use { receiver ->
                val plain = "post-rekey payload".encodeToByteArray()
                val wire = sender.encryptMessage(plain)
                assertContentEquals(plain, receiver.decryptMessage(wire))
            }
        }
    }
}
