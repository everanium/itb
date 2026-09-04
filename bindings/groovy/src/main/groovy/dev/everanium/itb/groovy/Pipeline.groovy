// Idiomatic Groovy lifetime + error surface over the Java binding's
// Triple Pipeline.

package dev.everanium.itb.groovy

import groovy.transform.CompileStatic
import groovy.transform.stc.ClosureParams
import groovy.transform.stc.SimpleType

import com.everanium.itb.Pipeline as JPipeline
import com.everanium.itb.Profile

/**
 * A Triple Pipeline session.
 *
 * <p>{@link #save} exports the self-describing session blob the
 * receiver feeds to {@link #load} / {@link #loadF}; {@link #rekey}
 * refreshes it. {@code close()} releases the native handle (libitb
 * zeroes key material internally), so the class composes with
 * Groovy's {@code withCloseable { }} and Java's try-with-resources;
 * the Java binding's Cleaner backstop reclaims an unclosed Pipeline.
 * The {@link #withPipeline} / {@link #withLoaded} factories scope
 * the whole lifetime inside a closure.</p>
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

    /** Reconstructs a Pipeline from a blob produced by {@link #save}
     * or {@link #rekey}, using the blob-embedded masters. The blob's
     * embedded profile record is the sole structural source. See
     * {@link #loadWithMasters} to override the masters. */
    static Pipeline load(byte[] blob) {
        ItbException.relay { new Pipeline(JPipeline.load(blob)) }
    }

    /** {@link #load} with explicit (non-empty) parallax + wrapper
     * masters overriding the blob-embedded ones; both must be
     * supplied. */
    static Pipeline loadWithMasters(byte[] blob, byte[] permMaster, byte[] wrapMaster) {
        ItbException.relay { new Pipeline(JPipeline.load(blob, permMaster, wrapMaster)) }
    }

    /** {@link #load} for a blob stored in a file; the file is read
     * inside the library. */
    static Pipeline loadF(String path) {
        ItbException.relay { new Pipeline(JPipeline.loadF(path)) }
    }

    /** {@link #loadF} with explicit (non-empty) parallax + wrapper
     * masters overriding the blob-embedded ones; both must be
     * supplied. */
    static Pipeline loadFWithMasters(String path, byte[] permMaster, byte[] wrapMaster) {
        ItbException.relay { new Pipeline(JPipeline.loadF(path, permMaster, wrapMaster)) }
    }

    /** Decodes the blob's embedded profile record without opening a
     * Pipeline. No registry read, no primitive probe. */
    static Profile inspect(byte[] blob) {
        ItbException.relay { JPipeline.inspect(blob) }
    }

    /** Registers {@code profile} under {@code name} so subsequent
     * {@link #init} / {@link #lookup} calls resolve it. Every field
     * rule is validated by Go; a duplicate name fails with
     * {@link Status#PROFILE_EXISTS}. */
    static void register(String name, Profile profile) {
        ItbException.relay { JPipeline.register(name, profile) }
    }

    /** {@link #register} from a Groovy named-argument map whose keys
     * are the record's setter names ({@code mode}, {@code width},
     * {@code hash}, {@code hashes}, {@code keyBits}, {@code mac},
     * {@code tagStub}, {@code chunk}, {@code wrapper}, {@code outer},
     * {@code parallax}, {@code palette}, {@code segment}):
     *
     * <pre>{@code
     * Pipeline.register('my-profile', mode: 'singlemsg-nomac', width: 512,
     *         hash: 'areion512', keyBits: 1024)
     * }</pre> */
    static void register(Map<String, ?> record, String name) {
        register(name, profileOf(record))
    }

    /** Builds a {@link Profile} record from a named-argument map (see
     * {@link #register(Map, String)}). List values fill the
     * {@code hashes} / {@code palette} arrays. */
    static Profile profileOf(Map<String, ?> record) {
        Profile profile = new Profile()
        record.each { String key, Object value ->
            switch (key) {
                case 'name': profile.name(String.valueOf(value)); break
                case 'mode': profile.mode(String.valueOf(value)); break
                case 'width': profile.width(((Number) value).intValue()); break
                case 'hash': profile.hash(String.valueOf(value)); break
                case 'hashes': profile.hashes(strings(value)); break
                case 'keyBits': profile.keyBits(((Number) value).intValue()); break
                case 'mac': profile.mac(String.valueOf(value)); break
                case 'tagStub': profile.tagStub(((Number) value).intValue()); break
                case 'chunk': profile.chunk(((Number) value).intValue()); break
                case 'wrapper': profile.wrapper((boolean) value); break
                case 'outer': profile.outer(String.valueOf(value)); break
                case 'parallax': profile.parallax((boolean) value); break
                case 'palette': profile.palette(strings(value)); break
                case 'segment': profile.segment(((Number) value).intValue()); break
                default: throw new IllegalArgumentException("itb: unknown profile key ${key}")
            }
        }
        profile
    }

    private static String[] strings(Object value) {
        value instanceof Iterable
                ? ((Iterable) value).collect { String.valueOf(it) } as String[]
                : [String.valueOf(value)] as String[]
    }

    /** Looks up a registered profile (shipped or {@link #register}ed)
     * by name; an unknown name fails with
     * {@link Status#UNKNOWN_PROFILE}. */
    static Profile lookup(String name) {
        ItbException.relay { JPipeline.lookup(name) }
    }

    /** The sorted names of every registered profile. */
    static List<String> profiles() {
        ItbException.relay { JPipeline.profiles() }
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

    /** Receiver-side counterpart of {@link #withPipeline}: load from
     * a blob, run the closure, close on the way out. */
    static <T> T withLoaded(byte[] blob,
            @ClosureParams(value = SimpleType, options = 'dev.everanium.itb.groovy.Pipeline')
            Closure<T> body) {
        Pipeline pipe = load(blob)
        try {
            body.call(pipe)
        } finally {
            pipe.close()
        }
    }

    /** The current self-describing session blob: the bytes
     * {@link #init} produced, the bytes {@link #load} re-marshalled,
     * or the bytes of the latest {@link #rekey}. */
    byte[] save() {
        ItbException.relay { underlying.save() }
    }

    /** Writes {@link #save} to {@code path} inside the library with
     * mode 0600; the containing directory must exist. */
    void saveF(String path) {
        ItbException.relay { underlying.saveF(path) }
    }

    /** Sets the worker cap for every subsequent cipher call.
     * {@code n} is clamped, never rejected: {@code n <= 0} selects
     * auto (CPU count), {@code n > 256} is treated as 256. Only the
     * handle statuses raise. */
    void maxWorkers(int n) {
        ItbException.relay { underlying.maxWorkers(n) }
    }

    /** Rotates the parallax + wrapper masters and returns the fresh
     * session blob (also available through {@link #save}). Must not
     * run concurrently with cipher calls or open stream sessions on
     * the same Pipeline. */
    byte[] rekey(byte[] permMaster, byte[] wrapMaster) {
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
