//! EncryptMessage throughput vs plaintext size (Single Message
//! profile).

use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use itb::{OptsBuilder, Pipeline};

fn bench_message(c: &mut Criterion) {
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
