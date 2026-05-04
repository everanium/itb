/*
 * internal.h — private helpers + concrete opaque-struct definitions.
 *
 * Not installed; consumers see only `itb.h` from the include/ directory.
 */
#ifndef ITB_INTERNAL_H
#define ITB_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "itb.h"
#include "itb_ffi.h"

/* ------------------------------------------------------------------ */
/* Concrete opaque types                                               */
/* ------------------------------------------------------------------ */

struct itb_seed {
    uintptr_t handle;
    char     *hash_name; /* malloc'd, NUL-terminated; freed in itb_seed_free */
};

struct itb_mac {
    uintptr_t handle;
    char     *name;      /* malloc'd, NUL-terminated; freed in itb_mac_free */
};

/*
 * Concrete encryptor handle.
 *
 * `handle`        carries the libitb Easy uintptr; zero after close.
 * `out_cache`     is a malloc'd output buffer reused across encrypt /
 *                 decrypt calls — pre-grown from a 1.25× upper bound on
 *                 the first cipher call so the size-probe round-trip is
 *                 skipped on the steady-state hot path.
 * `out_cache_cap` records the current allocated capacity in bytes;
 *                 grow-on-demand zeroes the previous buffer before
 *                 freeing it (wipe-on-grow contract — keeps the
 *                 most-recent ciphertext from lingering in heap garbage).
 * `closed`        flips to 1 once itb_encryptor_close has released the
 *                 libitb handle; subsequent public calls (other than
 *                 itb_encryptor_free) return ITB_EASY_CLOSED.
 */
struct itb_encryptor {
    uintptr_t handle;
    uint8_t  *out_cache;
    size_t    out_cache_cap;
    int       closed;
};

/* ------------------------------------------------------------------ */
/* Last-error capture (per-thread)                                     */
/* ------------------------------------------------------------------ */

/*
 * Captures `rc` and the libitb-side textual diagnostic into thread-
 * local storage. Returns `rc` unchanged so callers can compose:
 *
 *     if (rc != ITB_OK) return itb_internal_set_error(rc);
 */
itb_status_t itb_internal_set_error(int rc);

/*
 * Captures `rc` with a binding-side message (no libitb call required).
 * Used for input validation that fails before reaching FFI.
 */
itb_status_t itb_internal_set_error_msg(int rc, const char *msg);

/*
 * Resets thread-local last-error state to OK / "". Called by every
 * public entry point at the top so a successful call leaves the
 * thread-local accessor in a known state.
 */
void itb_internal_reset_error(void);

/* ------------------------------------------------------------------ */
/* String / byte readers (probe-then-allocate)                          */
/* ------------------------------------------------------------------ */

typedef int (*itb_internal_str_fn)(char *out, size_t cap, size_t *out_len, void *ctx);

/*
 * Probe-then-allocate idiom for libitb's size-out-param C-string
 * getters. The trailing NUL byte that libitb counts in *out_len is
 * stripped; *out_len_visible is the visible string length excluding the
 * NUL. The output is NUL-terminated regardless of stripping.
 *
 * Caller-side buffer pattern: caller passes (out, cap, out_len). When
 * out=NULL && cap=0, the helper probes and reports required size in
 * *out_len, returning ITB_BUFFER_TOO_SMALL. When out is non-NULL and
 * cap is sufficient, the helper writes the bytes and reports visible
 * length in *out_len (NUL-stripped).
 */
itb_status_t itb_internal_read_string(itb_internal_str_fn fn, void *ctx,
                                      char *out, size_t cap, size_t *out_len);

/* ------------------------------------------------------------------ */
/* Concrete blob structs (Phase 4B)                                    */
/* ------------------------------------------------------------------ */
/*
 * Three width-typed wrappers — one per native hash width. Each carries
 * the libitb uintptr handle; closed-state idiom does not apply (Blobs
 * are simple state containers, freed in one shot). The structs are
 * declared distinct (rather than typedef'd to a common shape) so the
 * public-header opaque-type contract `struct itb_blobN` matches a
 * unique definition per width — keeps the type safety of width-typed
 * handles all the way through the wrapper.
 */
struct itb_blob128 {
    uintptr_t handle;
};

struct itb_blob256 {
    uintptr_t handle;
};

struct itb_blob512 {
    uintptr_t handle;
};

#endif /* ITB_INTERNAL_H */
