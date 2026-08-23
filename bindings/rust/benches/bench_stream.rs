//! encrypt_stream_pump throughput vs plaintext size (Streaming AEAD
//! profile).

use std::io::Cursor;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use itb::{OptsBuilder, Pipeline, set_gc_percent, set_memory_limit};

fn bench_stream(c: &mut Criterion) {
    // Cap the Go runtime's heap for bench-scale allocation churn.
    // Without these, streaming a 16 MiB plaintext in tight
    // Criterion loops has the runtime hold arbitrarily large
    // scratch heaps between GC cycles.
    let _ = set_memory_limit(512 << 20);
    let _ = set_gc_percent(20);
    let pipe = Pipeline::init("streaming-aead-triple-mac-v1", &OptsBuilder::new()).unwrap();
    let mut group = c.benchmark_group("encrypt_stream_pump");
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(2));
    for size in [1usize << 10, 1 << 16, 1 << 20, 16 << 20] {
        let plain = vec![0x5Au8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{size}B"), |b| {
            b.iter(|| {
                let mut wire = Vec::with_capacity(size + size / 4 + 131_072);
                pipe.encrypt_stream_pump(Cursor::new(&plain), &mut wire)
                    .unwrap();
                wire
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_stream);
criterion_main!(benches);
