/* EncryptMessage throughput vs plaintext size (Single Message
 * profile) at 1 KiB / 64 KiB / 1 MiB / 16 MiB. */

#define _POSIX_C_SOURCE 200809L /* clock_gettime under -std=c11 */

#include <string.h>

#include "bench_util.h"

struct message_ctx {
    itb_pipeline *pipe;
    uint8_t *plain;
    size_t size;
};

static int run_message(void *raw)
{
    struct message_ctx *ctx = raw;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    itb_status st = itb_pipeline_encrypt_message(ctx->pipe, ctx->plain,
                                                 ctx->size, &wire, &wire_len);
    if (st != ITB_STATUS_OK) {
        return 1;
    }
    itb_bytes_free(wire);
    return 0;
}

int main(void)
{
    /* Bench-scale allocation churn leaks Go scratch heap unboundedly
     * without a soft memory cap + aggressive GC; the return values
     * report the previous settings, not an error. */
    (void)itb_set_memory_limit(512LL << 20); /* 512 MiB soft cap */
    (void)itb_set_gc_percent(20);            /* aggressive GC */

    itb_opts *opts = bench_build_opts();
    if (opts == NULL) {
        fprintf(stderr, "bench_message: opts alloc failed\n");
        return 1;
    }
    itb_pipeline *pipe = NULL;
    itb_status st = itb_pipeline_init(bench_profile_name("singlemsg-triple-nomac-v1"),
                                      opts, &pipe);
    if (st != ITB_STATUS_OK) {
        fprintf(stderr, "bench_message: init failed: %s\n", itb_last_error());
        itb_opts_free(opts);
        return 1;
    }
    itb_opts_free(opts);
    bench_header();
    static const size_t sizes[] = {
        (size_t)1 << 20, (size_t)16 << 20, (size_t)64 << 20,
    };
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        uint8_t *plain = malloc(sizes[i]);
        if (plain == NULL) {
            fprintf(stderr, "bench_message: out of memory\n");
            return 1;
        }
        memset(plain, 0xA5, sizes[i]);
        struct message_ctx ctx = { pipe, plain, sizes[i] };
        bench_case("message", sizes[i], run_message, &ctx);
        free(plain);
    }
    itb_pipeline_free(pipe);
    return 0;
}
