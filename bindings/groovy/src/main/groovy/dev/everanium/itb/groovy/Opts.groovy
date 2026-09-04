// Chainable options builder mirroring the Java binding's Opts.
//
// The builder performs no validation — every key and value is passed
// through to Go verbatim; libitb rejects unknown keys or bad values
// with a diagnostic surfaced via ItbException. Primitive / MAC /
// cipher / palette names are opaque strings.

package dev.everanium.itb.groovy

import groovy.transform.CompileStatic

import com.everanium.itb.Opts as JOpts

/**
 * Chainable options for {@link Pipeline#init}. An empty value renders
 * the empty query (pure profile defaults). Profile records for
 * {@link Pipeline#register} are built with
 * {@link com.everanium.itb.Profile} or {@link Pipeline#profileOf}.
 * Each {@code with*} call returns {@code this} for fluent chaining;
 * {@link #of} builds a value from a Groovy named-argument map:
 *
 * <pre>{@code
 * def opts = Opts.of(chunkSize: 4096, macName: 'some-mac')
 * }</pre>
 */
@CompileStatic
class Opts {

    private final List<List<String>> pairs = []

    /** Escape hatch appending a raw {@code key=value} pair. Covers
     * every key the Go side accepts. */
    Opts withRaw(String key, String value) {
        pairs << [key, value]
        this
    }

    /** Hex-encodes the parallax master override ({@code pm}). */
    Opts withPermMaster(byte[] master) {
        withRaw('pm', hex(master))
    }

    /** Hex-encodes the wrapper master override ({@code wm}). */
    Opts withWrapMaster(byte[] master) {
        withRaw('wm', hex(master))
    }

    Opts withParallax(boolean on) {
        withRaw('withParallax', Boolean.toString(on))
    }

    Opts withWrapper(boolean on) {
        withRaw('withWrapper', Boolean.toString(on))
    }

    Opts withMaxWorkers(long n) {
        withRaw('maxWorkers', Long.toString(n))
    }

    Opts withNonceBits(long n) {
        withRaw('nonceBits', Long.toString(n))
    }

    Opts withBarrierFill(long n) {
        withRaw('barrierFill', Long.toString(n))
    }

    Opts withChunkSize(long n) {
        withRaw('chunkSize', Long.toString(n))
    }

    Opts withKeyBits(long n) {
        withRaw('keyBits', Long.toString(n))
    }

    Opts withParallaxSegmentSize(long n) {
        withRaw('parallaxSegmentSize', Long.toString(n))
    }

    Opts withMacName(String name) {
        withRaw('macName', name)
    }

    Opts withInnerHash(String name) {
        withRaw('innerHash', name)
    }

    /** Per-call override for {@code Opts.MixedHashes [8]string} on
     * the Go side. Comma-joins the 8 slot names into the
     * {@code innerHashes} opts-string key. Slot ordering is
     * {@code [noise, lock, data1, data2, data3, start1, start2, start3]}.
     * Fail-fast validation surfaces at Init on the Go side; a typo'd
     * slot or width mismatch surfaces with an error naming the
     * offending slot. When both this and {@link #withInnerHash} are
     * set, the mixed override wins on the Go side. */
    Opts withInnerHashes(String... names) {
        withRaw('innerHashes', names.join(','))
    }

    Opts withOuterCipher(String name) {
        withRaw('outerCipher', name)
    }

    /** Comma-joins the palette names ({@code parallaxPalette}). */
    Opts withParallaxPalette(String... names) {
        withRaw('parallaxPalette', names.join(','))
    }

    /**
     * Builds an Opts from a named-argument map. Each entry becomes a
     * raw {@code key=value} pair in map iteration order: byte-array
     * values are hex-encoded (matching {@link #withPermMaster} /
     * {@link #withWrapMaster}); every other value is rendered with
     * {@code toString()}. Keys are relayed verbatim — the Go side
     * validates them.
     */
    static Opts of(Map<String, ?> entries) {
        Opts opts = new Opts()
        entries.each { String key, Object value ->
            opts.withRaw(key, value instanceof byte[] ? hex((byte[]) value) : String.valueOf(value))
        }
        opts
    }

    /** Replays the accumulated pairs into a fresh Java builder; the
     * Java side owns query rendering and percent-encoding. */
    protected JOpts toJava() {
        JOpts out = new JOpts()
        pairs.each { List<String> pair -> out.withRaw(pair[0], pair[1]) }
        out
    }

    @Override
    String toString() {
        "Opts(${toJava().build()})"
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2)
        for (byte b : bytes) {
            sb.append(String.format('%02x', b & 0xff))
        }
        sb.toString()
    }
}
