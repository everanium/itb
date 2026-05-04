/*
 * streams.c — chunked encrypt / decrypt over caller-owned read / write
 * callbacks.
 *
 * Mirrors Rust src/streams.rs / D src/itb/streams.d. ITB ciphertexts
 * cap at ~64 MB plaintext per chunk (the underlying container size
 * limit); streaming larger payloads slices the input into
 * chunk_size-sized blocks at the binding layer, encrypts each through
 * the regular itb_encrypt / itb_encrypt_auth FFI path, and
 * concatenates the results. The reverse operation walks a
 * concatenated chunk stream by reading the chunk header, calling
 * itb_parse_chunk_len to learn the chunk's body length, reading that
 * many bytes, and decrypting the single chunk.
 *
 * Free-function shape. The streams take Seeds (and an optional MAC),
 * NOT an itb_encryptor_t handle — matching the canonical
 * cross-binding contract codified in .NEXTBIND.md §11.k. The C# Phase
 * 5 attempt at handle-passing was rejected; the Rust / Python / D /
 * Ada source-of-truth shape is Seed-passing.
 *
 * Callback design. Caller supplies a (read_fn, user_ctx) pair for the
 * input source and a (write_fn, user_ctx) pair for the output sink;
 * the same pointer-style approach lets the caller carry state (file
 * descriptor, std::ostream, in-memory buffer, etc.) without globals.
 * read_fn signals EOF via *out_n = 0; write_fn must consume the full
 * (buf, n) span before returning. Either callback returning a
 * non-zero status code aborts the stream operation with ITB_INTERNAL.
 *
 * Memory peak. Bounded by chunk_size regardless of payload length.
 * The caller picks chunk_size explicitly (must be > 0; ITB_DEFAULT_CHUNK_SIZE
 * = 16 MiB is exposed in the public header as a recommended starting
 * value). The encrypt direction
 * allocates one read buffer (chunk_size bytes) plus one ciphertext
 * buffer per chunk via itb_encrypt; the decrypt direction grows an
 * accumulator buffer until a full chunk is available, then drains
 * it.
 *
 * Threading. A stream call is not thread-safe internally — its state
 * lives on the call stack and is single-threaded. Distinct stream
 * calls, each on its own thread, run independently against the
 * libitb worker pool.
 */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

/* Validates chunk_size against the cross-binding contract: zero is
 * rejected (mirroring Rust / D / Python which reject a zero-chunk
 * stream as malformed input). The caller passes the validated value
 * through to the inner loop unchanged. */
static itb_status_t validate_chunk_size(size_t chunk_size)
{
    if (chunk_size == 0) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "chunk_size must be > 0");
    }
    return ITB_OK;
}

/*
 * write_fn return-code translator. Surface caller's I/O failure via
 * ITB_INTERNAL with a fixed diagnostic; the caller's own context can
 * retrieve the precise underlying error via the (user_ctx) pointer.
 */
static itb_status_t io_write_error(int rc)
{
    (void) rc;
    return itb_internal_set_error_msg(
        ITB_INTERNAL, "stream write_fn reported I/O error");
}

static itb_status_t io_read_error(int rc)
{
    (void) rc;
    return itb_internal_set_error_msg(
        ITB_INTERNAL, "stream read_fn reported I/O error");
}

/* ------------------------------------------------------------------ */
/* Encrypt direction — Single Ouroboros                                 */
/* ------------------------------------------------------------------ */

static itb_status_t encrypt_emit_single(const itb_seed_t *noise,
                                        const itb_seed_t *data,
                                        const itb_seed_t *start,
                                        const uint8_t *chunk,
                                        size_t chunk_len,
                                        itb_stream_write_fn write_fn,
                                        void *write_ctx)
{
    uint8_t *ct = NULL;
    size_t ct_len = 0;
    itb_status_t st = itb_encrypt(noise, data, start, chunk, chunk_len,
                                  &ct, &ct_len);
    if (st != ITB_OK) {
        return st;
    }
    if (ct_len > 0) {
        int wrc = write_fn(write_ctx, ct, ct_len);
        if (wrc != 0) {
            free(ct);
            return io_write_error(wrc);
        }
    }
    free(ct);
    return ITB_OK;
}

static itb_status_t encrypt_loop_single(const itb_seed_t *noise,
                                        const itb_seed_t *data,
                                        const itb_seed_t *start,
                                        itb_stream_read_fn read_fn,
                                        void *read_ctx,
                                        itb_stream_write_fn write_fn,
                                        void *write_ctx,
                                        size_t chunk_size)
{
    uint8_t *buf = (uint8_t *) malloc(chunk_size);
    if (buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    size_t buffered = 0;

    for (;;) {
        /* Fill buf up to chunk_size, draining read_fn until either we
         * have a full chunk or read_fn signals EOF (*got = 0). */
        if (buffered < chunk_size) {
            size_t got = 0;
            int rrc = read_fn(read_ctx, buf + buffered,
                              chunk_size - buffered, &got);
            if (rrc != 0) {
                free(buf);
                return io_read_error(rrc);
            }
            if (got == 0) {
                /* EOF — flush partial chunk if any, then stop. */
                if (buffered > 0) {
                    itb_status_t st = encrypt_emit_single(
                        noise, data, start, buf, buffered,
                        write_fn, write_ctx);
                    if (st != ITB_OK) {
                        free(buf);
                        return st;
                    }
                }
                free(buf);
                itb_internal_reset_error();
                return ITB_OK;
            }
            buffered += got;
            continue;
        }
        /* buf is full — emit one chunk and reset. */
        itb_status_t st = encrypt_emit_single(
            noise, data, start, buf, chunk_size, write_fn, write_ctx);
        if (st != ITB_OK) {
            free(buf);
            return st;
        }
        buffered = 0;
    }
}

/* ------------------------------------------------------------------ */
/* Encrypt direction — Triple Ouroboros                                 */
/* ------------------------------------------------------------------ */

static itb_status_t encrypt_emit_triple(const itb_seed_t *noise,
                                        const itb_seed_t *data1,
                                        const itb_seed_t *data2,
                                        const itb_seed_t *data3,
                                        const itb_seed_t *start1,
                                        const itb_seed_t *start2,
                                        const itb_seed_t *start3,
                                        const uint8_t *chunk,
                                        size_t chunk_len,
                                        itb_stream_write_fn write_fn,
                                        void *write_ctx)
{
    uint8_t *ct = NULL;
    size_t ct_len = 0;
    itb_status_t st = itb_encrypt_triple(noise, data1, data2, data3,
                                         start1, start2, start3,
                                         chunk, chunk_len, &ct, &ct_len);
    if (st != ITB_OK) {
        return st;
    }
    if (ct_len > 0) {
        int wrc = write_fn(write_ctx, ct, ct_len);
        if (wrc != 0) {
            free(ct);
            return io_write_error(wrc);
        }
    }
    free(ct);
    return ITB_OK;
}

static itb_status_t encrypt_loop_triple(const itb_seed_t *noise,
                                        const itb_seed_t *data1,
                                        const itb_seed_t *data2,
                                        const itb_seed_t *data3,
                                        const itb_seed_t *start1,
                                        const itb_seed_t *start2,
                                        const itb_seed_t *start3,
                                        itb_stream_read_fn read_fn,
                                        void *read_ctx,
                                        itb_stream_write_fn write_fn,
                                        void *write_ctx,
                                        size_t chunk_size)
{
    uint8_t *buf = (uint8_t *) malloc(chunk_size);
    if (buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }
    size_t buffered = 0;

    for (;;) {
        if (buffered < chunk_size) {
            size_t got = 0;
            int rrc = read_fn(read_ctx, buf + buffered,
                              chunk_size - buffered, &got);
            if (rrc != 0) {
                free(buf);
                return io_read_error(rrc);
            }
            if (got == 0) {
                if (buffered > 0) {
                    itb_status_t st = encrypt_emit_triple(
                        noise, data1, data2, data3,
                        start1, start2, start3,
                        buf, buffered, write_fn, write_ctx);
                    if (st != ITB_OK) {
                        free(buf);
                        return st;
                    }
                }
                free(buf);
                itb_internal_reset_error();
                return ITB_OK;
            }
            buffered += got;
            continue;
        }
        itb_status_t st = encrypt_emit_triple(
            noise, data1, data2, data3,
            start1, start2, start3,
            buf, chunk_size, write_fn, write_ctx);
        if (st != ITB_OK) {
            free(buf);
            return st;
        }
        buffered = 0;
    }
}

/* ------------------------------------------------------------------ */
/* Decrypt direction — accumulator + drain                              */
/* ------------------------------------------------------------------ */

/* Grows the accumulator buffer to at least `need` bytes, reusing
 * existing capacity where possible. Returns ITB_OK on success or
 * ITB_INTERNAL on allocation failure. */
static itb_status_t accum_grow(uint8_t **buf, size_t *cap, size_t need)
{
    if (*cap >= need) return ITB_OK;
    size_t new_cap = (*cap == 0) ? 4096 : *cap;
    while (new_cap < need) {
        if (new_cap > SIZE_MAX / 2) {
            new_cap = need;
            break;
        }
        new_cap *= 2;
    }
    uint8_t *p = (uint8_t *) realloc(*buf, new_cap);
    if (p == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "realloc failed");
    }
    *buf = p;
    *cap = new_cap;
    /* Documents the post-condition for static analyzers (Phase 8 Agent 5
     * surfaced an interprocedural-aliasing FP class — `accum_grow`'s
     * `*buf != NULL` post-condition was not tracked across call boundaries
     * by gcc -fanalyzer / scan-build). Compiles out under -DNDEBUG. */
    assert(*buf != NULL);
    return ITB_OK;
}

/* Drops the consumed prefix of length `n` from the accumulator,
 * sliding the remaining bytes down. */
static void accum_consume(uint8_t *buf, size_t *len, size_t n)
{
    if (n >= *len) {
        *len = 0;
        return;
    }
    /* `buf` is non-NULL on every call site (`drain_single` / `drain_triple`
     * only reach here after `*len > 0`, which implies a prior `accum_grow`
     * has populated the accumulator). The assert documents the post-
     * condition for static analyzers; compiles out under -DNDEBUG. */
    assert(buf != NULL);
    memmove(buf, buf + n, *len - n);
    *len -= n;
}

/* Drains every full chunk currently sitting in the accumulator,
 * decrypting each and emitting plaintext via write_fn. Returns once
 * the buffer either holds < header_size bytes OR holds < chunk_len
 * bytes (announced by the header) — i.e. needs more input. */
static itb_status_t drain_single(const itb_seed_t *noise,
                                 const itb_seed_t *data,
                                 const itb_seed_t *start,
                                 size_t header_size,
                                 uint8_t *buf, size_t *buf_len,
                                 itb_stream_write_fn write_fn,
                                 void *write_ctx)
{
    for (;;) {
        if (*buf_len < header_size) return ITB_OK;
        size_t chunk_len = 0;
        itb_status_t st = itb_parse_chunk_len(buf, header_size, &chunk_len);
        if (st != ITB_OK) {
            return st;
        }
        if (chunk_len == 0 || *buf_len < chunk_len) return ITB_OK;

        uint8_t *pt = NULL;
        size_t pt_len = 0;
        st = itb_decrypt(noise, data, start, buf, chunk_len, &pt, &pt_len);
        if (st != ITB_OK) {
            return st;
        }
        if (pt_len > 0) {
            int wrc = write_fn(write_ctx, pt, pt_len);
            if (wrc != 0) {
                free(pt);
                return io_write_error(wrc);
            }
        }
        free(pt);
        accum_consume(buf, buf_len, chunk_len);
    }
}

static itb_status_t drain_triple(const itb_seed_t *noise,
                                 const itb_seed_t *data1,
                                 const itb_seed_t *data2,
                                 const itb_seed_t *data3,
                                 const itb_seed_t *start1,
                                 const itb_seed_t *start2,
                                 const itb_seed_t *start3,
                                 size_t header_size,
                                 uint8_t *buf, size_t *buf_len,
                                 itb_stream_write_fn write_fn,
                                 void *write_ctx)
{
    for (;;) {
        if (*buf_len < header_size) return ITB_OK;
        size_t chunk_len = 0;
        itb_status_t st = itb_parse_chunk_len(buf, header_size, &chunk_len);
        if (st != ITB_OK) {
            return st;
        }
        if (chunk_len == 0 || *buf_len < chunk_len) return ITB_OK;

        uint8_t *pt = NULL;
        size_t pt_len = 0;
        st = itb_decrypt_triple(noise, data1, data2, data3,
                                start1, start2, start3,
                                buf, chunk_len, &pt, &pt_len);
        if (st != ITB_OK) {
            return st;
        }
        if (pt_len > 0) {
            int wrc = write_fn(write_ctx, pt, pt_len);
            if (wrc != 0) {
                free(pt);
                return io_write_error(wrc);
            }
        }
        free(pt);
        accum_consume(buf, buf_len, chunk_len);
    }
}

static itb_status_t decrypt_loop_single(const itb_seed_t *noise,
                                        const itb_seed_t *data,
                                        const itb_seed_t *start,
                                        itb_stream_read_fn read_fn,
                                        void *read_ctx,
                                        itb_stream_write_fn write_fn,
                                        void *write_ctx,
                                        size_t chunk_size)
{
    /* Snapshot the chunk-header size at call entry; switching nonce
     * bits mid-stream would invalidate this. Same contract as Rust
     * StreamDecryptor::new. */
    int hsz_int = itb_header_size();
    if (hsz_int <= 0) {
        return itb_internal_set_error_msg(
            ITB_INTERNAL, "itb_header_size returned non-positive value");
    }
    size_t header_size = (size_t) hsz_int;

    uint8_t *accum = NULL;
    size_t accum_cap = 0;
    size_t accum_len = 0;

    uint8_t *read_buf = (uint8_t *) malloc(chunk_size);
    if (read_buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }

    for (;;) {
        size_t got = 0;
        int rrc = read_fn(read_ctx, read_buf, chunk_size, &got);
        if (rrc != 0) {
            free(read_buf);
            free(accum);
            return io_read_error(rrc);
        }
        if (got == 0) {
            /* EOF — accumulator must be empty for a clean stream. A
             * non-empty tail at EOF is a half-chunk error (mirrors
             * Rust StreamDecryptor::close). */
            itb_status_t st = ITB_OK;
            if (accum_len > 0) {
                st = itb_internal_set_error_msg(
                    ITB_BAD_INPUT,
                    "stream decrypt: trailing bytes do not form a complete chunk");
            }
            free(read_buf);
            free(accum);
            if (st == ITB_OK) {
                itb_internal_reset_error();
            }
            return st;
        }
        /* Append `got` bytes to the accumulator. */
        itb_status_t gst = accum_grow(&accum, &accum_cap, accum_len + got);
        if (gst != ITB_OK) {
            free(read_buf);
            free(accum);
            return gst;
        }
        /* `accum_grow` guarantees `accum != NULL` on ITB_OK; restate for
         * the analyzer (interprocedural-aliasing FP class — the
         * helper's post-condition is not tracked across the call). */
        assert(accum != NULL);
        memcpy(accum + accum_len, read_buf, got);
        accum_len += got;

        itb_status_t dst = drain_single(noise, data, start,
                                        header_size,
                                        accum, &accum_len,
                                        write_fn, write_ctx);
        if (dst != ITB_OK) {
            free(read_buf);
            free(accum);
            return dst;
        }
    }
}

static itb_status_t decrypt_loop_triple(const itb_seed_t *noise,
                                        const itb_seed_t *data1,
                                        const itb_seed_t *data2,
                                        const itb_seed_t *data3,
                                        const itb_seed_t *start1,
                                        const itb_seed_t *start2,
                                        const itb_seed_t *start3,
                                        itb_stream_read_fn read_fn,
                                        void *read_ctx,
                                        itb_stream_write_fn write_fn,
                                        void *write_ctx,
                                        size_t chunk_size)
{
    int hsz_int = itb_header_size();
    if (hsz_int <= 0) {
        return itb_internal_set_error_msg(
            ITB_INTERNAL, "itb_header_size returned non-positive value");
    }
    size_t header_size = (size_t) hsz_int;

    uint8_t *accum = NULL;
    size_t accum_cap = 0;
    size_t accum_len = 0;

    uint8_t *read_buf = (uint8_t *) malloc(chunk_size);
    if (read_buf == NULL) {
        return itb_internal_set_error_msg(ITB_INTERNAL, "malloc failed");
    }

    for (;;) {
        size_t got = 0;
        int rrc = read_fn(read_ctx, read_buf, chunk_size, &got);
        if (rrc != 0) {
            free(read_buf);
            free(accum);
            return io_read_error(rrc);
        }
        if (got == 0) {
            itb_status_t st = ITB_OK;
            if (accum_len > 0) {
                st = itb_internal_set_error_msg(
                    ITB_BAD_INPUT,
                    "stream decrypt: trailing bytes do not form a complete chunk");
            }
            free(read_buf);
            free(accum);
            if (st == ITB_OK) {
                itb_internal_reset_error();
            }
            return st;
        }
        itb_status_t gst = accum_grow(&accum, &accum_cap, accum_len + got);
        if (gst != ITB_OK) {
            free(read_buf);
            free(accum);
            return gst;
        }
        /* `accum_grow` guarantees `accum != NULL` on ITB_OK; restate for
         * the analyzer (interprocedural-aliasing FP class). */
        assert(accum != NULL);
        memcpy(accum + accum_len, read_buf, got);
        accum_len += got;

        itb_status_t dst = drain_triple(
            noise, data1, data2, data3,
            start1, start2, start3,
            header_size, accum, &accum_len, write_fn, write_ctx);
        if (dst != ITB_OK) {
            free(read_buf);
            free(accum);
            return dst;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Argument validation helpers                                         */
/* ------------------------------------------------------------------ */

static itb_status_t validate_callbacks(itb_stream_read_fn read_fn,
                                       itb_stream_write_fn write_fn)
{
    if (read_fn == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "read_fn callback is NULL");
    }
    if (write_fn == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "write_fn callback is NULL");
    }
    return ITB_OK;
}

/* ------------------------------------------------------------------ */
/* Public entry points                                                 */
/* ------------------------------------------------------------------ */

itb_status_t itb_stream_encrypt(const itb_seed_t *noise,
                                const itb_seed_t *data,
                                const itb_seed_t *start,
                                itb_stream_read_fn read_fn, void *read_user_ctx,
                                itb_stream_write_fn write_fn, void *write_user_ctx,
                                size_t chunk_size)
{
    if (noise == NULL || data == NULL || start == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "noise/data/start seed is NULL");
    }
    itb_status_t cv = validate_callbacks(read_fn, write_fn);
    if (cv != ITB_OK) return cv;
    itb_status_t sv = validate_chunk_size(chunk_size);
    if (sv != ITB_OK) return sv;
    return encrypt_loop_single(noise, data, start,
                               read_fn, read_user_ctx,
                               write_fn, write_user_ctx,
                               chunk_size);
}

itb_status_t itb_stream_decrypt(const itb_seed_t *noise,
                                const itb_seed_t *data,
                                const itb_seed_t *start,
                                itb_stream_read_fn read_fn, void *read_user_ctx,
                                itb_stream_write_fn write_fn, void *write_user_ctx,
                                size_t chunk_size)
{
    if (noise == NULL || data == NULL || start == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "noise/data/start seed is NULL");
    }
    itb_status_t cv = validate_callbacks(read_fn, write_fn);
    if (cv != ITB_OK) return cv;
    itb_status_t sv = validate_chunk_size(chunk_size);
    if (sv != ITB_OK) return sv;
    return decrypt_loop_single(noise, data, start,
                               read_fn, read_user_ctx,
                               write_fn, write_user_ctx,
                               chunk_size);
}

itb_status_t itb_stream_encrypt_triple(const itb_seed_t *noise,
                                       const itb_seed_t *data1,
                                       const itb_seed_t *data2,
                                       const itb_seed_t *data3,
                                       const itb_seed_t *start1,
                                       const itb_seed_t *start2,
                                       const itb_seed_t *start3,
                                       itb_stream_read_fn read_fn,
                                       void *read_user_ctx,
                                       itb_stream_write_fn write_fn,
                                       void *write_user_ctx,
                                       size_t chunk_size)
{
    if (noise == NULL || data1 == NULL || data2 == NULL || data3 == NULL ||
        start1 == NULL || start2 == NULL || start3 == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "one of the seven seeds is NULL");
    }
    itb_status_t cv = validate_callbacks(read_fn, write_fn);
    if (cv != ITB_OK) return cv;
    itb_status_t sv = validate_chunk_size(chunk_size);
    if (sv != ITB_OK) return sv;
    return encrypt_loop_triple(noise, data1, data2, data3,
                               start1, start2, start3,
                               read_fn, read_user_ctx,
                               write_fn, write_user_ctx,
                               chunk_size);
}

itb_status_t itb_stream_decrypt_triple(const itb_seed_t *noise,
                                       const itb_seed_t *data1,
                                       const itb_seed_t *data2,
                                       const itb_seed_t *data3,
                                       const itb_seed_t *start1,
                                       const itb_seed_t *start2,
                                       const itb_seed_t *start3,
                                       itb_stream_read_fn read_fn,
                                       void *read_user_ctx,
                                       itb_stream_write_fn write_fn,
                                       void *write_user_ctx,
                                       size_t chunk_size)
{
    if (noise == NULL || data1 == NULL || data2 == NULL || data3 == NULL ||
        start1 == NULL || start2 == NULL || start3 == NULL) {
        return itb_internal_set_error_msg(
            ITB_BAD_INPUT, "one of the seven seeds is NULL");
    }
    itb_status_t cv = validate_callbacks(read_fn, write_fn);
    if (cv != ITB_OK) return cv;
    itb_status_t sv = validate_chunk_size(chunk_size);
    if (sv != ITB_OK) return sv;
    return decrypt_loop_triple(noise, data1, data2, data3,
                               start1, start2, start3,
                               read_fn, read_user_ctx,
                               write_fn, write_user_ctx,
                               chunk_size);
}

