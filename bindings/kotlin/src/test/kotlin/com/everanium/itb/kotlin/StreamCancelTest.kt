// Mid-flight session cancellation: closing a session with buffered
// input leaves the parent Pipeline fully usable.

package com.everanium.itb.kotlin

import kotlin.test.Test
import kotlin.test.assertContentEquals

class StreamCancelTest {

    @Test
    fun cancelledSessionLeavesPipelineUsable() {
        Pipeline.init("streaming-aead-triple-mac-v1").use { sender ->
            Pipeline.load(sender.save()).use { receiver ->
                // Open a session, feed it, and abandon it un-ended.
                val session = sender.encryptStream()
                session.write(ByteArray(50_000) { (it % 199).toByte() })
                session.close()
                // Idempotent close.
                session.close()

                // The pipeline still encrypts and the receiver still
                // decrypts after the cancelled session.
                val plain = "post-cancel payload".encodeToByteArray()
                val wire = sender.encryptStreamOneShot(plain)
                assertContentEquals(plain, receiver.decryptStreamOneShot(wire))
            }
        }
    }
}
