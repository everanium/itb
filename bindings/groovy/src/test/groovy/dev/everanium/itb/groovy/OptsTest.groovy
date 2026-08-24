// Opts builder behavior: chaining, the named-argument map factory,
// byte-array hex encoding, and pass-through of a typed setter on a
// live init.

package dev.everanium.itb.groovy

import groovy.transform.CompileStatic

import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.assertArrayEquals
import static org.junit.jupiter.api.Assertions.assertEquals

@CompileStatic
class OptsTest {

    @Test
    void chainedBuilderRenders() {
        def opts = new Opts()
                .withChunkSize(4096)
                .withMacName('some-mac')
                .withParallax(false)
        assertEquals('Opts(chunkSize=4096&macName=some-mac&withParallax=false)',
                opts.toString())
    }

    @Test
    void mapFactoryMatchesChainedBuilder() {
        def chained = new Opts().withChunkSize(4096).withKeyBits(1024)
        def mapped = Opts.of(chunkSize: 4096, keyBits: 1024)
        assertEquals(chained.toString(), mapped.toString())
    }

    @Test
    void mapFactoryHexEncodesByteArrays() {
        byte[] master = [0x00, 0x0f, (byte) 0xff] as byte[]
        assertEquals(new Opts().withPermMaster(master).toString(),
                Opts.of(pm: master).toString())
        assertEquals('Opts(pm=000fff)', Opts.of(pm: master).toString())
    }

    @Test
    void typedSetterReachesGo() {
        // A small chunkSize accepted by Go proves the rendered query
        // string reaches libitb intact.
        def opts = new Opts().withChunkSize(4096)
        Pipeline.withPipeline('streaming-aead-triple-mac-v1', opts) { Pipeline sender ->
            Pipeline.withOpened('streaming-aead-triple-mac-v1', sender.blob, opts) { Pipeline receiver ->
                byte[] plain = MessageTest.payload(20_000, 3)
                byte[] wire = sender.encryptStreamOneShot(plain)
                assertArrayEquals(plain, receiver.decryptStreamOneShot(wire))
            }
        }
    }
}
