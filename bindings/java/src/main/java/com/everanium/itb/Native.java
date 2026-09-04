// JNI declaration bundle for the libitb ITB_Triple_* surface.
//
// Every native method is a direct proxy to one prototype in
// cmd/cshared/libitb.h. Buffers cross the boundary as direct
// ByteBuffers (zero-copy at the JNI layer; the public wrappers copy
// heap byte arrays in and out of direct buffers). Strings cross as
// NUL-terminated UTF-8 bytes in a direct buffer so the shim needs no
// JNI string machinery. Scalar out-params come back through
// single-element long[] / int[] arrays.
//
// The shim library (libitb_jni.so) is resolved at class load:
//
//   1. ITB_JNI_PATH environment variable (absolute path to the shim).
//   2. System.loadLibrary("itb_jni") over java.library.path.
//
// libitb.so itself is a link-time dependency of the shim, found via
// the shim's RPATH (the repository dist directory) or the OS loader
// path.

package com.everanium.itb;

import java.lang.ref.Cleaner;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

final class Native {

    /** Shared cleaner for Pipeline / stream-session handle release. */
    static final Cleaner CLEANER = Cleaner.create();

    private Native() {
    }

    static {
        String p = System.getenv("ITB_JNI_PATH");
        if (p != null && !p.isEmpty()) {
            System.load(p);
        } else {
            System.loadLibrary("itb_jni");
        }
    }

    // ── auxiliaries ─────────────────────────────────────────────────
    static native int version(ByteBuffer out, long cap, long[] outLen);

    static native int lastError(ByteBuffer out, long cap, long[] outLen);

    static native long setMemoryLimit(long limit);

    static native int setGCPercent(int pct);

    // ── Triple Pipeline lifecycle ───────────────────────────────────
    static native int tripleInit(ByteBuffer profile, ByteBuffer opts,
            ByteBuffer blobOut, long blobCap, long[] blobLen, long[] outHandle);

    static native int tripleLoad(ByteBuffer blob, long blobLen,
            ByteBuffer permMaster, long permLen,
            ByteBuffer wrapMaster, long wrapLen, long mastersCount, long[] outHandle);

    static native int tripleLoadF(ByteBuffer path,
            ByteBuffer permMaster, long permLen,
            ByteBuffer wrapMaster, long wrapLen, long mastersCount, long[] outHandle);

    static native int tripleSave(long handle, ByteBuffer blobOut, long blobCap, long[] blobLen);

    static native int tripleSaveF(long handle, ByteBuffer path);

    static native int tripleInspect(ByteBuffer blob, long blobLen,
            ByteBuffer jsonOut, long jsonCap, long[] jsonLen);

    static native int tripleMaxWorkers(long handle, int n);

    static native int tripleRekey(long handle, ByteBuffer permMaster, long permLen,
            ByteBuffer wrapMaster, long wrapLen,
            ByteBuffer blobOut, long blobCap, long[] blobLen);

    static native int tripleClose(long handle);

    static native int tripleFree(long handle);

    // ── profile registry ────────────────────────────────────────────
    static native int tripleRegister(ByteBuffer name, ByteBuffer profileJson);

    static native int tripleLookup(ByteBuffer name, ByteBuffer jsonOut, long jsonCap,
            long[] jsonLen);

    static native int tripleProfiles(ByteBuffer jsonOut, long jsonCap, long[] jsonLen);

    // ── one-shot cipher calls ───────────────────────────────────────
    static native int tripleEncryptStream(long handle, ByteBuffer src, long srcLen,
            ByteBuffer out, long outCap, long[] outLen);

    static native int tripleDecryptStream(long handle, ByteBuffer src, long srcLen,
            ByteBuffer out, long outCap, long[] outLen);

    static native int tripleEncryptMessage(long handle, ByteBuffer src, long srcLen,
            ByteBuffer out, long outCap, long[] outLen);

    static native int tripleDecryptMessage(long handle, ByteBuffer src, long srcLen,
            ByteBuffer out, long outCap, long[] outLen);

    // ── incremental stream sessions ─────────────────────────────────
    static native int tripleEncryptStreamBegin(long pipe, long[] outStream);

    static native int tripleDecryptStreamBegin(long pipe, long[] outStream);

    static native int tripleStreamWrite(long stream, ByteBuffer src, long srcLen);

    static native int tripleStreamEnd(long stream);

    static native int tripleStreamRead(long stream, ByteBuffer out, long outCap,
            long[] outLen, int[] finished);

    static native int tripleStreamFree(long stream);

    // ── helpers shared by the wrapper classes ───────────────────────

    /** Renders a Java string as NUL-terminated UTF-8 in a direct buffer. */
    static ByteBuffer cstr(String s) {
        byte[] utf8 = s.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buf = ByteBuffer.allocateDirect(utf8.length + 1);
        buf.put(utf8).put((byte) 0);
        return buf;
    }

    /** Copies a heap array into a fresh direct buffer (empty array → null,
     * which the Go side treats as an absent buffer). */
    static ByteBuffer direct(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return null;
        }
        ByteBuffer buf = ByteBuffer.allocateDirect(bytes.length);
        buf.put(bytes);
        return buf;
    }

    /** Copies the first {@code len} bytes of a direct buffer out to a heap array. */
    static byte[] toArray(ByteBuffer buf, int len) {
        byte[] out = new byte[len];
        buf.position(0);
        buf.get(out, 0, len);
        return out;
    }

    /** Reads the process-global ITB_LastError diagnostic. Empty string
     * when no diagnostic is recorded. */
    static String readLastError() {
        long[] need = new long[1];
        int rc = lastError(null, 0, need);
        if ((rc != Status.OK.code() && rc != Status.BUFFER_TOO_SMALL.code()) || need[0] <= 1) {
            return "";
        }
        ByteBuffer buf = ByteBuffer.allocateDirect((int) need[0]);
        rc = lastError(buf, buf.capacity(), need);
        if (rc != Status.OK.code()) {
            return "";
        }
        return new String(toArray(buf, (int) need[0] - 1), StandardCharsets.UTF_8);
    }

    /** Two-phase read over the (out, cap, *outLen) C-string contract:
     * probe with null / 0 for the required capacity, then read and
     * strip the trailing NUL. */
    interface CStringCall {
        int invoke(ByteBuffer out, long cap, long[] outLen);
    }

    static String readCString(CStringCall call) {
        long[] need = new long[1];
        int rc = call.invoke(null, 0, need);
        if (rc != Status.OK.code() && rc != Status.BUFFER_TOO_SMALL.code()) {
            throw ItbException.of(rc);
        }
        if (need[0] <= 1) {
            return "";
        }
        ByteBuffer buf = ByteBuffer.allocateDirect((int) need[0]);
        ItbException.check(call.invoke(buf, buf.capacity(), need));
        return new String(toArray(buf, (int) need[0] - 1), StandardCharsets.UTF_8);
    }
}
