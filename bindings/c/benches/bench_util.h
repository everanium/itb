/*
 * bench_util.h — shared timing + reporting helpers for the C binding
 * micro-benchmarks. Wall-clock via clock_gettime(CLOCK_MONOTONIC);
 * output is a fixed-width table:
 *
 *   bench             size     mb_per_sec
 *   message           1 KiB    <n>
 *   ...
 */

#ifndef ITB_BENCH_UTIL_H
#define ITB_BENCH_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "itb.h"

/* Per-case wall-clock budget (seconds) and iteration floor. */
#define BENCH_MIN_SECONDS 2.0
#define BENCH_MIN_ITERS   3

static double bench_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void bench_header(void)
{
    printf("%-17s %-8s %s\n", "bench", "size", "mb_per_sec");
}

static const char *bench_size_label(size_t size)
{
    static char label[32];
    if (size >= ((size_t)1 << 20)) {
        (void)snprintf(label, sizeof(label), "%zu MiB", size >> 20);
    } else {
        (void)snprintf(label, sizeof(label), "%zu KiB", size >> 10);
    }
    return label;
}

/* Runs fn(ctx) until the wall-clock budget is spent (with an
 * iteration floor + one untimed warm-up), then prints one table row.
 * fn returns 0 on success; a failure aborts the process. */
static void bench_case(const char *name, size_t size,
                       int (*fn)(void *ctx), void *ctx)
{
    if (fn(ctx) != 0) { /* warm-up */
        fprintf(stderr, "bench %s @%zu: warm-up failed: %s\n", name, size,
                itb_last_error());
        exit(1);
    }
    double start = bench_now();
    double elapsed = 0.0;
    size_t iters = 0;
    while (elapsed < BENCH_MIN_SECONDS || iters < BENCH_MIN_ITERS) {
        if (fn(ctx) != 0) {
            fprintf(stderr, "bench %s @%zu: iteration failed: %s\n", name,
                    size, itb_last_error());
            exit(1);
        }
        iters++;
        elapsed = bench_now() - start;
    }
    double mb = (double)size * (double)iters / (1024.0 * 1024.0);
    printf("%-17s %-8s %.1f\n", name, bench_size_label(size), mb / elapsed);
}

#endif /* ITB_BENCH_UTIL_H */
