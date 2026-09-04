/* itb_jni.c — JNI shim between com.everanium.itb.Native and the
 * libitb shared library's ITB_Triple_* surface (cmd/cshared).
 *
 * Deliberately mechanical: every function extracts direct-buffer
 * addresses and scalars, forwards them to the matching libitb export,
 * and copies scalar out-params back into single-element Java arrays.
 * No validation, no logic — the Go side owns both.
 *
 * Strings arrive as NUL-terminated UTF-8 bytes inside direct buffers
 * (composed on the Java side), so no JNI string machinery is needed;
 * the only JNI buffer primitive used is GetDirectBufferAddress, which
 * is zero-copy and never blocks the collector during the (potentially
 * long) libitb call.
 *
 * Compile-time linked against libitb (-litb) with an RPATH pointing
 * at the repository dist directory; see build.gradle.kts.
 */

#include <jni.h>
#include <stddef.h>
#include <stdint.h>

#include <libitb.h>

/* Direct-buffer address, or NULL for a null jobject (the Go side
 * treats a NULL/0 buffer as absent). */
static void *addr(JNIEnv *env, jobject buf) {
    return buf == NULL ? NULL : (*env)->GetDirectBufferAddress(env, buf);
}

/* Writes one size_t out-param back into a long[1]. */
static void set_long(JNIEnv *env, jlongArray arr, size_t v) {
    jlong val = (jlong)v;
    (*env)->SetLongArrayRegion(env, arr, 0, 1, &val);
}

/* Writes one int out-param back into an int[1]. */
static void set_int(JNIEnv *env, jintArray arr, int v) {
    jint val = (jint)v;
    (*env)->SetIntArrayRegion(env, arr, 0, 1, &val);
}

/* ── auxiliaries ──────────────────────────────────────────────────── */

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_version(
    JNIEnv *env, jclass cls, jobject out, jlong cap, jlongArray outLen) {
    (void)cls;
    size_t n = 0;
    int rc = ITB_Version((char *)addr(env, out), (size_t)cap, &n);
    set_long(env, outLen, n);
    return rc;
}

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_lastError(
    JNIEnv *env, jclass cls, jobject out, jlong cap, jlongArray outLen) {
    (void)cls;
    size_t n = 0;
    int rc = ITB_LastError((char *)addr(env, out), (size_t)cap, &n);
    set_long(env, outLen, n);
    return rc;
}

JNIEXPORT jlong JNICALL Java_com_everanium_itb_Native_setMemoryLimit(
    JNIEnv *env, jclass cls, jlong limit) {
    (void)env;
    (void)cls;
    return (jlong)ITB_SetMemoryLimit((int64_t)limit);
}

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_setGCPercent(
    JNIEnv *env, jclass cls, jint pct) {
    (void)env;
    (void)cls;
    return ITB_SetGCPercent((int)pct);
}

/* ── Triple Pipeline lifecycle ────────────────────────────────────── */

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_tripleInit(
    JNIEnv *env, jclass cls, jobject profile, jobject opts,
    jobject blobOut, jlong blobCap, jlongArray blobLen, jlongArray outHandle) {
    (void)cls;
    size_t n = 0;
    uintptr_t handle = 0;
    int rc = ITB_Triple_Init((char *)addr(env, profile), (char *)addr(env, opts),
                             addr(env, blobOut), (size_t)blobCap, &n, &handle);
    set_long(env, blobLen, n);
    set_long(env, outHandle, (size_t)handle);
    return rc;
}

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_tripleLoad(
    JNIEnv *env, jclass cls, jobject blob, jlong blobLen,
    jobject permMaster, jlong permLen,
    jobject wrapMaster, jlong wrapLen, jlong mastersCount, jlongArray outHandle) {
    (void)cls;
    uintptr_t handle = 0;
    int rc = ITB_Triple_Load(addr(env, blob), (size_t)blobLen,
                             addr(env, permMaster), (size_t)permLen,
                             addr(env, wrapMaster), (size_t)wrapLen,
                             (size_t)mastersCount, &handle);
    set_long(env, outHandle, (size_t)handle);
    return rc;
}

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_tripleLoadF(
    JNIEnv *env, jclass cls, jobject path,
    jobject permMaster, jlong permLen,
    jobject wrapMaster, jlong wrapLen, jlong mastersCount, jlongArray outHandle) {
    (void)cls;
    uintptr_t handle = 0;
    int rc = ITB_Triple_LoadF((char *)addr(env, path),
                              addr(env, permMaster), (size_t)permLen,
                              addr(env, wrapMaster), (size_t)wrapLen,
                              (size_t)mastersCount, &handle);
    set_long(env, outHandle, (size_t)handle);
    return rc;
}

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_tripleSave(
    JNIEnv *env, jclass cls, jlong handle, jobject blobOut, jlong blobCap,
    jlongArray blobLen) {
    (void)cls;
    size_t n = 0;
    int rc = ITB_Triple_Save((uintptr_t)handle, addr(env, blobOut), (size_t)blobCap, &n);
    set_long(env, blobLen, n);
    return rc;
}

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_tripleSaveF(
    JNIEnv *env, jclass cls, jlong handle, jobject path) {
    (void)cls;
    return ITB_Triple_SaveF((uintptr_t)handle, (char *)addr(env, path));
}

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_tripleInspect(
    JNIEnv *env, jclass cls, jobject blob, jlong blobLen,
    jobject jsonOut, jlong jsonCap, jlongArray jsonLen) {
    (void)cls;
    size_t n = 0;
    int rc = ITB_Triple_Inspect(addr(env, blob), (size_t)blobLen,
                                addr(env, jsonOut), (size_t)jsonCap, &n);
    set_long(env, jsonLen, n);
    return rc;
}

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_tripleMaxWorkers(
    JNIEnv *env, jclass cls, jlong handle, jint n) {
    (void)env;
    (void)cls;
    return ITB_Triple_MaxWorkers((uintptr_t)handle, (int)n);
}

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_tripleRekey(
    JNIEnv *env, jclass cls, jlong handle, jobject permMaster, jlong permLen,
    jobject wrapMaster, jlong wrapLen,
    jobject blobOut, jlong blobCap, jlongArray blobLen) {
    (void)cls;
    size_t n = 0;
    int rc = ITB_Triple_Rekey((uintptr_t)handle,
                              addr(env, permMaster), (size_t)permLen,
                              addr(env, wrapMaster), (size_t)wrapLen,
                              addr(env, blobOut), (size_t)blobCap, &n);
    set_long(env, blobLen, n);
    return rc;
}

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_tripleClose(
    JNIEnv *env, jclass cls, jlong handle) {
    (void)env;
    (void)cls;
    return ITB_Triple_Close((uintptr_t)handle);
}

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_tripleFree(
    JNIEnv *env, jclass cls, jlong handle) {
    (void)env;
    (void)cls;
    return ITB_Triple_Free((uintptr_t)handle);
}

/* ── profile registry ─────────────────────────────────────────────── */

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_tripleRegister(
    JNIEnv *env, jclass cls, jobject name, jobject profileJson) {
    (void)cls;
    return ITB_Triple_Register((char *)addr(env, name),
                               (char *)addr(env, profileJson));
}

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_tripleLookup(
    JNIEnv *env, jclass cls, jobject name, jobject jsonOut, jlong jsonCap,
    jlongArray jsonLen) {
    (void)cls;
    size_t n = 0;
    int rc = ITB_Triple_Lookup((char *)addr(env, name),
                               addr(env, jsonOut), (size_t)jsonCap, &n);
    set_long(env, jsonLen, n);
    return rc;
}

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_tripleProfiles(
    JNIEnv *env, jclass cls, jobject jsonOut, jlong jsonCap, jlongArray jsonLen) {
    (void)cls;
    size_t n = 0;
    int rc = ITB_Triple_Profiles(addr(env, jsonOut), (size_t)jsonCap, &n);
    set_long(env, jsonLen, n);
    return rc;
}

/* ── one-shot cipher calls ────────────────────────────────────────── */

#define CIPHER_SHIM(java_name, itb_name)                                    \
    JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_##java_name(       \
        JNIEnv *env, jclass cls, jlong handle, jobject src, jlong srcLen,   \
        jobject out, jlong outCap, jlongArray outLen) {                     \
        (void)cls;                                                          \
        size_t n = 0;                                                       \
        int rc = itb_name((uintptr_t)handle, addr(env, src), (size_t)srcLen,\
                          addr(env, out), (size_t)outCap, &n);              \
        set_long(env, outLen, n);                                           \
        return rc;                                                          \
    }

CIPHER_SHIM(tripleEncryptStream, ITB_Triple_EncryptStream)
CIPHER_SHIM(tripleDecryptStream, ITB_Triple_DecryptStream)
CIPHER_SHIM(tripleEncryptMessage, ITB_Triple_EncryptMessage)
CIPHER_SHIM(tripleDecryptMessage, ITB_Triple_DecryptMessage)

/* ── incremental stream sessions ──────────────────────────────────── */

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_tripleEncryptStreamBegin(
    JNIEnv *env, jclass cls, jlong pipe, jlongArray outStream) {
    (void)cls;
    uintptr_t stream = 0;
    int rc = ITB_Triple_EncryptStreamBegin((uintptr_t)pipe, &stream);
    set_long(env, outStream, (size_t)stream);
    return rc;
}

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_tripleDecryptStreamBegin(
    JNIEnv *env, jclass cls, jlong pipe, jlongArray outStream) {
    (void)cls;
    uintptr_t stream = 0;
    int rc = ITB_Triple_DecryptStreamBegin((uintptr_t)pipe, &stream);
    set_long(env, outStream, (size_t)stream);
    return rc;
}

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_tripleStreamWrite(
    JNIEnv *env, jclass cls, jlong stream, jobject src, jlong srcLen) {
    (void)cls;
    return ITB_Triple_StreamWrite((uintptr_t)stream, addr(env, src),
                                  (size_t)srcLen);
}

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_tripleStreamEnd(
    JNIEnv *env, jclass cls, jlong stream) {
    (void)env;
    (void)cls;
    return ITB_Triple_StreamEnd((uintptr_t)stream);
}

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_tripleStreamRead(
    JNIEnv *env, jclass cls, jlong stream, jobject out, jlong outCap,
    jlongArray outLen, jintArray finished) {
    (void)cls;
    size_t n = 0;
    int fin = 0;
    int rc = ITB_Triple_StreamRead((uintptr_t)stream, addr(env, out),
                                   (size_t)outCap, &n, &fin);
    set_long(env, outLen, n);
    set_int(env, finished, fin);
    return rc;
}

JNIEXPORT jint JNICALL Java_com_everanium_itb_Native_tripleStreamFree(
    JNIEnv *env, jclass cls, jlong stream) {
    (void)env;
    (void)cls;
    return ITB_Triple_StreamFree((uintptr_t)stream);
}
