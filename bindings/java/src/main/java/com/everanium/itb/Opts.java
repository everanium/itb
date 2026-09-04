// URL-query builder for the opts pass-through string.

package com.everanium.itb;

import java.util.ArrayList;
import java.util.List;

/**
 * Fluent builder producing the URL-query-encoded opts string consumed
 * by {@link Pipeline#init}. Profile records for
 * {@link Pipeline#register} are built with {@link Profile}.
 *
 * <p>The builder performs no validation — every key and value is
 * rendered into a percent-encoded query string and passed through to
 * Go verbatim; libitb rejects unknown keys or bad values with a
 * diagnostic surfaced via {@link ItbException}. Primitive / MAC /
 * cipher / palette names are opaque strings.</p>
 */
public final class Opts {

    private final List<String> pairs = new ArrayList<>();

    /** Hex-encodes the parallax master override ({@code pm}). */
    public Opts withPermMaster(byte[] master) {
        return withRaw("pm", hex(master));
    }

    /** Hex-encodes the wrapper master override ({@code wm}). */
    public Opts withWrapMaster(byte[] master) {
        return withRaw("wm", hex(master));
    }

    public Opts withParallax(boolean on) {
        return withRaw("withParallax", Boolean.toString(on));
    }

    public Opts withWrapper(boolean on) {
        return withRaw("withWrapper", Boolean.toString(on));
    }

    public Opts withMaxWorkers(long n) {
        return withRaw("maxWorkers", Long.toString(n));
    }

    public Opts withNonceBits(long n) {
        return withRaw("nonceBits", Long.toString(n));
    }

    public Opts withBarrierFill(long n) {
        return withRaw("barrierFill", Long.toString(n));
    }

    public Opts withChunkSize(long n) {
        return withRaw("chunkSize", Long.toString(n));
    }

    public Opts withKeyBits(long n) {
        return withRaw("keyBits", Long.toString(n));
    }

    public Opts withParallaxSegmentSize(long n) {
        return withRaw("parallaxSegmentSize", Long.toString(n));
    }

    public Opts withMacName(String name) {
        return withRaw("macName", name);
    }

    public Opts withInnerHash(String name) {
        return withRaw("innerHash", name);
    }

    /** Per-call override for {@code Opts.MixedHashes [8]string} on
     * the Go side. Comma-joins the 8 slot names into the
     * {@code innerHashes} opts-string key. Slot ordering is
     * {@code [noise, lock, data1, data2, data3, start1, start2, start3]}.
     * Fail-fast validation surfaces at Init on the Go side; a typo'd
     * slot or width mismatch surfaces with an error naming the
     * offending slot. When both this and {@link #withInnerHash} are
     * set, the mixed override wins on the Go side. */
    public Opts withInnerHashes(String... names) {
        return withRaw("innerHashes", String.join(",", names));
    }

    public Opts withOuterCipher(String name) {
        return withRaw("outerCipher", name);
    }

    /** Comma-joins the palette names ({@code parallaxPalette}). */
    public Opts withParallaxPalette(String... names) {
        return withRaw("parallaxPalette", String.join(",", names));
    }

    /** Escape hatch appending a raw {@code key=value} pair. Covers
     * every key the Go side accepts. */
    public Opts withRaw(String key, String value) {
        pairs.add(enc(key) + "=" + enc(value));
        return this;
    }

    /** Renders the accumulated pairs as a query string. */
    public String build() {
        return String.join("&", pairs);
    }

    @Override
    public String toString() {
        return "Opts(" + build() + ")";
    }

    /** Minimal percent-encoding: the accepted values are ASCII names,
     * decimal integers, {@code true} / {@code false}, hex, and
     * comma-separated lists, so everything outside the URL-safe subset
     * (plus {@code ,}) is escaped byte-wise over UTF-8. */
    private static String enc(String s) {
        StringBuilder out = new StringBuilder(s.length());
        for (byte raw : s.getBytes(java.nio.charset.StandardCharsets.UTF_8)) {
            int b = raw & 0xFF;
            boolean safe = (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
                    || (b >= '0' && b <= '9')
                    || b == '-' || b == '.' || b == '_' || b == '~' || b == ',';
            if (safe) {
                out.append((char) b);
            } else {
                out.append('%').append(String.format("%02X", b));
            }
        }
        return out.toString();
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(String.format("%02x", b));
        }
        return out.toString();
    }
}
