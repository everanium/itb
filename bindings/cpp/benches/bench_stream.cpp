/* encrypt_stream_pump throughput vs plaintext size (Streaming
 * Non-AEAD profile) at 1 MiB / 16 MiB / 64 MiB. */

#include <exception>

#include "bench_util.hpp"

int main()
{
    try {
        /* Bench-scale allocation churn leaks Go scratch heap
         * unboundedly without a soft memory cap + aggressive GC; the
         * return values report the previous settings, not an error. */
        (void)itb::set_memory_limit(512LL << 20); /* 512 MiB soft cap */
        (void)itb::set_gc_percent(20);            /* aggressive GC */

        itb::Pipeline pipe = itb::Pipeline::init(
            bench_profile_name("streaming-noaead-triple-v1"),
            bench_build_opts());
        bench_header();
        static const std::size_t sizes[] = {
            std::size_t{1} << 20, std::size_t{16} << 20, std::size_t{64} << 20,
        };
        for (std::size_t size : sizes) {
            std::vector<std::uint8_t> plain(size);
            bench_csprng_fill(plain);
            bench_case("stream_pump", size, [&] {
                (void)pipe.encrypt_stream_pump(itb::as_bytes(plain));
            });
        }
        return 0;
    } catch (const std::exception &e) {
        std::fprintf(stderr, "bench_stream: %s\n", e.what());
        return 1;
    }
}
