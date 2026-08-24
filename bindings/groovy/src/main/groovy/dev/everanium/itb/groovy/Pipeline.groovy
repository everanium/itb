// Idiomatic Groovy lifetime + error surface over the Java binding's
// Triple Pipeline.

package dev.everanium.itb.groovy

import groovy.transform.CompileStatic
import groovy.transform.stc.ClosureParams
import groovy.transform.stc.SimpleType

import com.everanium.itb.Pipeline as JPipeline

/**
 * A Triple Pipeline session plus its exported blob bytes.
 *
 * <p>The blob carries the session bundle the receiver feeds to
 * {@link #open}; {@link #rekey} refreshes it. {@code close()}
 * releases the native handle (libitb zeroes key material
 * internally), so the class composes with Groovy's
 * {@code withCloseable { }} and Java's try-with-resources; the Java
 * binding's Cleaner backstop reclaims an unclosed Pipeline. The
 * {@link #withPipeline} / {@link #withOpened} factories scope the
 * whole lifetime inside a closure.</p>
 *
 * <p>Every failing libitb call surfaces as {@link ItbException}
 * carrying the structural {@link Status} plus the diagnostic
 * text.</p>
 *
 * <p>Streaming-decrypt caveat: chunked Streaming AEAD verifies per
 * chunk, so plaintext of verified chunks is released before a later
 * chunk can fail authentication.</p>
 */
@CompileStatic
final class Pipeline implements AutoCloseable {

    private final JPipeline underlying

    private Pipeline(JPipeline underlying) {
        this.underlying = underlying
    }

    /** Constructs a fresh Pipeline against the named profile. */
    static Pipeline init(String profile, Opts opts = new Opts()) {
        ItbException.relay { new Pipeline(JPipeline.init(profile, opts.toJava())) }
    }

    /** Reconstructs a Pipeline from a blob produced by {@link #init}
     * or {@link #rekey}, using the blob-embedded masters. See
     * {@link #openWithMasters} to override them. */
    static Pipeline open(String profile, byte[] blob, Opts opts = new Opts()) {
        ItbException.relay { new Pipeline(JPipeline.open(profile, blob, opts.toJava())) }
    }

    /** {@link #open} with explicit (non-empty) parallax + wrapper
     * masters overriding the blob-embedded ones; both must be
     * supplied. */
    static Pipeline openWithMasters(String profile, byte[] blob, Opts opts,
            byte[] permMaster, byte[] wrapMaster) {
        ItbException.relay {
            new Pipeline(JPipeline.open(profile, blob, opts.toJava(), permMaster, wrapMaster))
        }
    }

    /** Registers a user-defined Triple profile under {@code name} so
     * subsequent {@link #init} / {@link #open} calls resolve it. The
     * opts follow the register-profile grammar validated by Go —
     * build them with {@link Opts#withRaw} / {@link Opts#of} plus the
     * typed setters where key names coincide. A duplicate name fails
     * with {@link Status#PROFILE_EXISTS}. */
    static void registerProfile(String name, Opts opts) {
        ItbException.relay { JPipeline.registerProfile(name, opts.toJava()) }
    }

    /** Scopes a fresh Pipeline inside {@code body}: init, run the
     * closure with the Pipeline as its argument, close on the way
     * out. Returns the closure's value. */
    static <T> T withPipeline(String profile, Opts opts = new Opts(),
            @ClosureParams(value = SimpleType, options = 'dev.everanium.itb.groovy.Pipeline')
            Closure<T> body) {
        Pipeline pipe = init(profile, opts)
        try {
            body.call(pipe)
        } finally {
            pipe.close()
        }
    }

    /** Receiver-side counterpart of {@link #withPipeline}: open from
     * a blob, run the closure, close on the way out. */
    static <T> T withOpened(String profile, byte[] blob, Opts opts = new Opts(),
            @ClosureParams(value = SimpleType, options = 'dev.everanium.itb.groovy.Pipeline')
            Closure<T> body) {
        Pipeline pipe = open(profile, blob, opts)
        try {
            body.call(pipe)
        } finally {
            pipe.close()
        }
    }

    /** The exported session bundle bytes for the receiver side. */
    byte[] getBlob() {
        underlying.blob()
    }

    /** Rotates the parallax + wrapper masters and refreshes
     * {@link #getBlob}. Must not run concurrently with cipher calls
     * or open stream sessions on the same Pipeline. */
    void rekey(byte[] permMaster, byte[] wrapMaster) {
        ItbException.relay { underlying.rekey(permMaster, wrapMaster) }
    }

    /** Zeroes the Pipeline's key material and marks it closed while
     * keeping the handle registered. Idempotent; subsequent cipher
     * calls fail with {@link Status#TRIPLE_CLOSED}. The native handle
     * itself is released by {@link #close}. */
    void destroy() {
        ItbException.relay { underlying.destroy() }
    }

    /** True once {@link #destroy} has zeroed the key material. */
    boolean isDestroyed() {
        underlying.destroyed
    }

    /** Single Message encrypt: one call, one self-contained wire. */
    byte[] encryptMessage(byte[] plaintext) {
        ItbException.relay { underlying.encryptMessage(plaintext) }
    }

    /** Receive-side counterpart of {@link #encryptMessage}. */
    byte[] decryptMessage(byte[] wire) {
        ItbException.relay { underlying.decryptMessage(wire) }
    }

    /** One-shot stream encrypt for callers holding the whole
     * plaintext in memory. For bounded-memory streaming use
     * {@link #encryptStream} / {@link #encryptStreamPump}. */
    byte[] encryptStreamOneShot(byte[] plaintext) {
        ItbException.relay { underlying.encryptStreamOneShot(plaintext) }
    }

    /** Receive-side counterpart of {@link #encryptStreamOneShot}. */
    byte[] decryptStreamOneShot(byte[] wire) {
        ItbException.relay { underlying.decryptStreamOneShot(wire) }
    }

    /** Opens an incremental encrypt session (plaintext in, wire out).
     * The session holds a reference to this Pipeline, keeping it
     * reachable while the session is live. */
    EncryptStream encryptStream() {
        ItbException.relay { new EncryptStream(this, underlying.encryptStream()) }
    }

    /** Opens an incremental decrypt session (wire in, plaintext out).
     * The session holds a reference to this Pipeline, keeping it
     * reachable while the session is live. */
    DecryptStream decryptStream() {
        ItbException.relay { new DecryptStream(this, underlying.decryptStream()) }
    }

    /** Scopes an encrypt session inside {@code body}: open, run the
     * closure with the session as its argument, close (cancel) on
     * the way out. Returns the closure's value. */
    <T> T encrypting(
            @ClosureParams(value = SimpleType, options = 'dev.everanium.itb.groovy.EncryptStream')
            Closure<T> body) {
        EncryptStream session = encryptStream()
        try {
            body.call(session)
        } finally {
            session.close()
        }
    }

    /** Receive-side counterpart of {@link #encrypting}. */
    <T> T decrypting(
            @ClosureParams(value = SimpleType, options = 'dev.everanium.itb.groovy.DecryptStream')
            Closure<T> body) {
        DecryptStream session = decryptStream()
        try {
            body.call(session)
        } finally {
            session.close()
        }
    }

    /** Pumps {@code src} through an encrypt session into {@code dst}
     * with bounded memory: feed a slice, drain available wire,
     * repeat; end + final drain on source EOF. The session is freed
     * on return. */
    void encryptStreamPump(InputStream src, OutputStream dst) {
        ItbException.relay { underlying.encryptStreamPump(src, dst) }
    }

    /** Receive-side counterpart of {@link #encryptStreamPump}. */
    void decryptStreamPump(InputStream src, OutputStream dst) {
        ItbException.relay { underlying.decryptStreamPump(src, dst) }
    }

    /** Releases the native handle (libitb closes it first, zeroing
     * key material). Idempotent. */
    @Override
    void close() {
        underlying.close()
    }
}
