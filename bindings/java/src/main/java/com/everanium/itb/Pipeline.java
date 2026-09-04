// AutoCloseable wrapper around the Triple Pipeline handle.

package com.everanium.itb;

import java.io.InputStream;
import java.io.OutputStream;
import java.lang.ref.Cleaner;
import java.lang.ref.Reference;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.security.auth.Destroyable;

/**
 * A Triple Pipeline session.
 *
 * <p>{@link #save} exports the self-describing session blob the
 * receiver feeds to {@link #load} / {@link #loadF}; {@link #rekey}
 * refreshes it. {@link #close} (or GC via
 * {@link java.lang.ref.Cleaner}) frees the handle — libitb zeroes
 * key material internally. {@link #destroy} zeroes the key material
 * while keeping the handle registered; subsequent cipher calls fail
 * with {@link Status#TRIPLE_CLOSED}.</p>
 *
 * <p>Streaming-decrypt caveat: chunked Streaming AEAD verifies per
 * chunk, so plaintext of verified chunks is released before a later
 * chunk can fail authentication.</p>
 */
public final class Pipeline implements AutoCloseable, Destroyable {

    /** Floor capacity for blob output buffers (Init / Save / Rekey). */
    private static final int BLOB_CAP = 64 * 1024;

    /** Floor capacity for profile-JSON output buffers (Inspect /
     * Lookup / Profiles). */
    private static final int JSON_CAP = 4 * 1024;

    private final long handle;
    private final Cleaner.Cleanable cleanable;
    private boolean destroyed;

    /** Cleaner action: holds only the raw handle so the action cannot
     * pin the Pipeline itself. Cleanable.clean() runs at most once. */
    private static final class Handle implements Runnable {
        final long value;

        Handle(long value) {
            this.value = value;
        }

        @Override
        public void run() {
            Native.tripleFree(value);
        }
    }

    private Pipeline(long handle) {
        this.handle = handle;
        this.cleanable = Native.CLEANER.register(this, new Handle(handle));
    }

    /** Constructs a fresh Pipeline against the named profile with
     * default opts. */
    public static Pipeline init(String profile) {
        return init(profile, new Opts());
    }

    /** Constructs a fresh Pipeline against the named profile. On a
     * blob-buffer retry the Init re-runs and yields a fresh session
     * (the undersized attempt is closed by libitb before returning).
     * The session blob is available through {@link #save}. */
    public static Pipeline init(String profile, Opts opts) {
        ByteBuffer profileC = Native.cstr(profile);
        ByteBuffer optsC = Native.cstr(opts.build());
        long[] handle = new long[1];
        retryOnce(BLOB_CAP, (buf, cap, len) ->
                Native.tripleInit(profileC, optsC, buf, cap, len, handle));
        return new Pipeline(handle[0]);
    }

    /** Reconstructs a Pipeline from a blob produced by {@link #save}
     * or {@link #rekey}, using the blob-embedded masters. The blob's
     * embedded profile record is the sole structural source. */
    public static Pipeline load(byte[] blob) {
        return load(blob, null, null);
    }

    /** Reconstructs a Pipeline from a blob produced by {@link #save}
     * or {@link #rekey}. Pass both masters as {@code null} to use the
     * blob-embedded masters, or both non-empty to override them. */
    public static Pipeline load(byte[] blob, byte[] permMaster, byte[] wrapMaster) {
        ByteBuffer blobC = Native.direct(blob);
        ByteBuffer pmC = Native.direct(permMaster);
        ByteBuffer wmC = Native.direct(wrapMaster);
        long[] handle = new long[1];
        ItbException.check(Native.tripleLoad(blobC,
                blob == null ? 0 : blob.length,
                pmC, permMaster == null ? 0 : permMaster.length,
                wmC, wrapMaster == null ? 0 : wrapMaster.length,
                mastersCount(permMaster, wrapMaster), handle));
        return new Pipeline(handle[0]);
    }

    /** {@link #load} for a blob stored in a file; the file is read
     * inside the library. */
    public static Pipeline loadF(String path) {
        return loadF(path, null, null);
    }

    /** {@link #load} for a blob stored in a file, with the same
     * masters semantics. */
    public static Pipeline loadF(String path, byte[] permMaster, byte[] wrapMaster) {
        ByteBuffer pathC = Native.cstr(path);
        ByteBuffer pmC = Native.direct(permMaster);
        ByteBuffer wmC = Native.direct(wrapMaster);
        long[] handle = new long[1];
        ItbException.check(Native.tripleLoadF(pathC,
                pmC, permMaster == null ? 0 : permMaster.length,
                wmC, wrapMaster == null ? 0 : wrapMaster.length,
                mastersCount(permMaster, wrapMaster), handle));
        return new Pipeline(handle[0]);
    }

    /** Folds the optional master pair into the CAPI arity flag: 0 for
     * none, 2 for both. */
    private static long mastersCount(byte[] permMaster, byte[] wrapMaster) {
        if (permMaster == null && wrapMaster == null) {
            return 0;
        }
        if (permMaster == null || permMaster.length == 0
                || wrapMaster == null || wrapMaster.length == 0) {
            throw new IllegalArgumentException(
                    "itb: master override arrays must both be non-empty");
        }
        return 2;
    }

    /** Decodes the blob's embedded profile record without opening a
     * Pipeline. No registry read, no primitive probe. */
    public static Profile inspect(byte[] blob) {
        ByteBuffer blobC = Native.direct(blob);
        byte[] json = retryOnce(JSON_CAP, (buf, cap, len) ->
                Native.tripleInspect(blobC, blob == null ? 0 : blob.length, buf, cap, len));
        return Profile.fromJson(Profile.utf8(json));
    }

    /** Registers {@code profile} under {@code name} so subsequent
     * {@link #init} / {@link #lookup} calls resolve it. Every field
     * rule is validated by Go; a duplicate name fails with
     * {@link Status#PROFILE_EXISTS}. */
    public static void register(String name, Profile profile) {
        ItbException.check(Native.tripleRegister(
                Native.cstr(name), Native.cstr(profile.toJson())));
    }

    /** Looks up a registered profile (shipped or {@link #register}ed)
     * by name; an unknown name fails with
     * {@link Status#UNKNOWN_PROFILE}. */
    public static Profile lookup(String name) {
        ByteBuffer nameC = Native.cstr(name);
        byte[] json = retryOnce(JSON_CAP, (buf, cap, len) ->
                Native.tripleLookup(nameC, buf, cap, len));
        return Profile.fromJson(Profile.utf8(json));
    }

    /** The sorted names of every registered profile. */
    public static List<String> profiles() {
        byte[] json = retryOnce(JSON_CAP, Native::tripleProfiles);
        return Profile.stringsFromJson(Profile.utf8(json));
    }

    /** The current self-describing session blob: the bytes
     * {@link #init} produced, the bytes {@link #load} re-marshalled,
     * or the bytes of the latest {@link #rekey}. */
    public byte[] save() {
        try {
            return retryOnce(BLOB_CAP, (buf, cap, len) ->
                    Native.tripleSave(handle, buf, cap, len));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /** Writes {@link #save} to {@code path} inside the library with
     * mode 0600; the containing directory must exist. */
    public void saveF(String path) {
        try {
            ItbException.check(Native.tripleSaveF(handle, Native.cstr(path)));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /** Sets the worker cap for every subsequent cipher call. {@code n}
     * is clamped, never rejected: {@code n <= 0} selects auto
     * (CPU count), {@code n > 256} is treated as 256. Only the handle
     * statuses raise. */
    public void maxWorkers(int n) {
        try {
            ItbException.check(Native.tripleMaxWorkers(handle, n));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /** Rotates the parallax + wrapper masters and returns the fresh
     * session blob (also available through {@link #save}). Must not
     * run concurrently with cipher calls or open stream sessions on
     * the same Pipeline. */
    public byte[] rekey(byte[] permMaster, byte[] wrapMaster) {
        ByteBuffer pmC = Native.direct(permMaster);
        ByteBuffer wmC = Native.direct(wrapMaster);
        try {
            return retryOnce(BLOB_CAP, (buf, cap, len) ->
                    Native.tripleRekey(handle,
                            pmC, permMaster == null ? 0 : permMaster.length,
                            wmC, wrapMaster == null ? 0 : wrapMaster.length,
                            buf, cap, len));
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    /** Zeroes the Pipeline's key material and marks it closed while
     * keeping the handle registered. Idempotent; subsequent cipher
     * calls fail with {@link Status#TRIPLE_CLOSED}. */
    @Override
    public void destroy() {
        try {
            ItbException.check(Native.tripleClose(handle));
            destroyed = true;
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    /** Single Message encrypt: one call, one self-contained wire. */
    public byte[] encryptMessage(byte[] plaintext) {
        return cipher(Native::tripleEncryptMessage, plaintext);
    }

    /** Receive-side counterpart of {@link #encryptMessage}. */
    public byte[] decryptMessage(byte[] wire) {
        return cipher(Native::tripleDecryptMessage, wire);
    }

    /** One-shot stream encrypt for callers holding the whole plaintext
     * in memory. For bounded-memory streaming use
     * {@link #encryptStream()} / {@link #encryptStreamPump}. */
    public byte[] encryptStreamOneShot(byte[] plaintext) {
        return cipher(Native::tripleEncryptStream, plaintext);
    }

    /** Receive-side counterpart of {@link #encryptStreamOneShot}. */
    public byte[] decryptStreamOneShot(byte[] wire) {
        return cipher(Native::tripleDecryptStream, wire);
    }

    /** Single Message encrypt into a caller-supplied writable direct
     * {@link ByteBuffer}: the wire lands between {@code dst.position()}
     * and {@code dst.limit()} with no output allocation and no
     * copy-out; the position advances by the returned byte count.
     * Size {@code dst} for the wire-expansion envelope
     * {@code max(131072, len * 5/4 + 131072)}; an undersized buffer
     * fails with {@link Status#BUFFER_TOO_SMALL} (nothing is written
     * past the limit). A heap, read-only, or spent buffer is rejected
     * with {@link IllegalArgumentException}. */
    public int encryptMessageInto(byte[] plaintext, ByteBuffer dst) {
        return cipherInto(Native::tripleEncryptMessage, plaintext, dst);
    }

    /** Receive-side counterpart of {@link #encryptMessageInto}. Size
     * {@code dst} for at least the plaintext length. */
    public int decryptMessageInto(byte[] wire, ByteBuffer dst) {
        return cipherInto(Native::tripleDecryptMessage, wire, dst);
    }

    /** One-shot stream encrypt into a caller-supplied direct buffer;
     * same contract as {@link #encryptMessageInto}. */
    public int encryptStreamOneShotInto(byte[] plaintext, ByteBuffer dst) {
        return cipherInto(Native::tripleEncryptStream, plaintext, dst);
    }

    /** Receive-side counterpart of {@link #encryptStreamOneShotInto}. */
    public int decryptStreamOneShotInto(byte[] wire, ByteBuffer dst) {
        return cipherInto(Native::tripleDecryptStream, wire, dst);
    }

    /** Opens an incremental encrypt session (plaintext in, wire out). */
    public EncryptStream encryptStream() {
        return new EncryptStream(this);
    }

    /** Opens an incremental decrypt session (wire in, plaintext out). */
    public DecryptStream decryptStream() {
        return new DecryptStream(this);
    }

    /** Pumps {@code src} through an encrypt session into {@code dst}
     * with bounded memory: feed a slice, drain available wire, repeat;
     * end + final drain on source EOF. The session is freed on return. */
    public void encryptStreamPump(InputStream src, OutputStream dst) {
        try (EncryptStream sess = encryptStream()) {
            sess.pump(src, dst);
        }
    }

    /** Receive-side counterpart of {@link #encryptStreamPump}. */
    public void decryptStreamPump(InputStream src, OutputStream dst) {
        try (DecryptStream sess = decryptStream()) {
            sess.pump(src, dst);
        }
    }

    /** Frees the Go-side handle (libitb closes it first, zeroing key
     * material). Idempotent; safe concurrently with GC. */
    @Override
    public void close() {
        cleanable.clean();
    }

    long rawHandle() {
        return handle;
    }

    /** Pre-allocation formula for Message / one-shot stream outputs:
     * {@code max(131072, payload * 5/4 + 131072)}. */
    private static int outCap(int payload) {
        return Math.max(131_072, payload + payload / 4 + 131_072);
    }

    /** Pooled direct scratch pair for the cipher entries (src copy-in
     * + wire out), grown on demand and retained for the Pipeline's
     * lifetime. Taken with an atomic swap so sequential callers reuse
     * one pair allocation-free while concurrent callers fall back to
     * fresh buffers — the Go side's per-Pipeline cipher concurrency is
     * preserved without a lock. */
    private static final class Scratch {
        private ByteBuffer src;
        private ByteBuffer out;

        ByteBuffer src(int cap) {
            if (src == null || src.capacity() < cap) {
                src = ByteBuffer.allocateDirect(cap);
            }
            return src;
        }

        ByteBuffer out(int cap) {
            if (out == null || out.capacity() < cap) {
                out = ByteBuffer.allocateDirect(cap);
            }
            return out;
        }
    }

    private final AtomicReference<Scratch> scratchPool =
            new AtomicReference<>(new Scratch());

    private Scratch takeScratch() {
        Scratch s = scratchPool.getAndSet(null);
        return s != null ? s : new Scratch();
    }

    /** Copies {@code src} into the pooled direct in-scratch; empty
     * input maps to {@code null} (the Go side's absent-buffer form). */
    private static ByteBuffer fillSrc(Scratch s, byte[] src) {
        if (src.length == 0) {
            return null;
        }
        ByteBuffer in = s.src(src.length);
        in.clear();
        in.put(src, 0, src.length);
        return in;
    }

    /** Shared body for the four buffer-in / buffer-out cipher entries. */
    private byte[] cipher(CipherCall call, byte[] src) {
        Scratch s = takeScratch();
        try {
            ByteBuffer in = fillSrc(s, src);
            ByteBuffer out = s.out(outCap(src.length));
            long[] len = new long[1];
            int rc = call.invoke(handle, in, src.length, out, out.capacity(), len);
            if (rc == Status.BUFFER_TOO_SMALL.code() && len[0] > out.capacity()) {
                out = s.out((int) len[0]);
                rc = call.invoke(handle, in, src.length, out, out.capacity(), len);
            }
            ItbException.check(rc);
            return Native.toArray(out, (int) len[0]);
        } finally {
            scratchPool.set(s);
            Reference.reachabilityFence(this);
        }
    }

    /** Shared body for the {@code *Into} cipher entries: output lands
     * directly in the caller's direct buffer, so the call performs no
     * output allocation and no copy-out. */
    private int cipherInto(CipherCall call, byte[] src, ByteBuffer dst) {
        checkDst(dst);
        Scratch s = takeScratch();
        try {
            ByteBuffer in = fillSrc(s, src);
            // The writable window is dst.position()..dst.limit(); the
            // slice's own base address carries the position offset, and
            // its capacity caps the native write — libitb never writes
            // past it (Ruby-style out-of-bounds guard).
            ByteBuffer window = dst.slice();
            long[] len = new long[1];
            ItbException.check(call.invoke(handle, in, src.length,
                    window, window.capacity(), len));
            dst.position(dst.position() + (int) len[0]);
            return (int) len[0];
        } finally {
            scratchPool.set(s);
            Reference.reachabilityFence(this);
        }
    }

    /** Validates a caller-supplied {@code *Into} output buffer. */
    private static void checkDst(ByteBuffer dst) {
        if (dst == null || !dst.isDirect() || dst.isReadOnly()) {
            throw new IllegalArgumentException(
                    "itb: dst must be a writable direct ByteBuffer");
        }
        if (!dst.hasRemaining()) {
            throw new IllegalArgumentException(
                    "itb: dst has no remaining capacity");
        }
    }

    private interface CipherCall {
        int invoke(long handle, ByteBuffer src, long srcLen,
                ByteBuffer out, long outCap, long[] outLen);
    }

    private interface OutCall {
        int invoke(ByteBuffer out, long cap, long[] outLen);
    }

    /** Single retry-once dispatch site for every variable-size output
     * buffer: pre-allocate {@code cap}, and on BUFFER_TOO_SMALL retry
     * once with the exact size the FFI reported through the length
     * out-param. The retry is gated on the reported length strictly
     * exceeding the current capacity, guarding against a stray report
     * with {@code len <= cap}. */
    private static byte[] retryOnce(int cap, OutCall call) {
        ByteBuffer buf = ByteBuffer.allocateDirect(cap);
        long[] len = new long[1];
        int rc = call.invoke(buf, cap, len);
        if (rc == Status.BUFFER_TOO_SMALL.code() && len[0] > cap) {
            buf = ByteBuffer.allocateDirect((int) len[0]);
            rc = call.invoke(buf, buf.capacity(), len);
        }
        ItbException.check(rc);
        return Native.toArray(buf, (int) len[0]);
    }
}
