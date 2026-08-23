//! EncryptMessage throughput vs plaintext size (Single Message
//! profile).

use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use itb::{OptsBuilder, Pipeline, set_gc_percent, set_memory_limit};

fn bench_message(c: &mut Criterion) {
    // Cap the Go runtime's heap for bench-scale allocation churn.
    // Without these, encrypting a 16 MiB plaintext in tight
    // Criterion loops has the runtime hold arbitrarily large
    // scratch heaps between GC cycles.
    let _ = set_memory_limit(512 << 20);
    let _ = set_gc_percent(20);
    let pipe = Pipeline::init("singlemsg-triple-mac-v1", &OptsBuilder::new()).unwrap();
    let mut group = c.benchmark_group("encrypt_message");
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(2));
    for size in [1usize << 10, 1 << 16, 1 << 20, 16 << 20] {
        let plain = vec![0xA5u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{size}B"), |b| {
            b.iter(|| pipe.encrypt_message(&plain).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, bench_message);
criterion_main!(benches);
