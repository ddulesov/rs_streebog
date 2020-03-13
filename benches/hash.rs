extern crate hex;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use streebog::{Digest, Streebog256, Streebog512 };


pub fn streebog512_benchmark(c: &mut Criterion) {
    let input = black_box(b"012345678901234567890123456789012345678901234567890123456789012");
    c.bench_function("streebog 512", |b| b.iter(||{  
            let mut h512 = Streebog512::new();
            h512.input(input);
            let _result = h512.finish();
    }));
}

pub fn streebog256_benchmark(c: &mut Criterion) {
    let input = black_box(b"012345678901234567890123456789012345678901234567890123456789012");
    c.bench_function("streebog 256", |b| b.iter(||{  
            let mut h512 = Streebog256::new();
            h512.input(input);
            let _result = h512.finish();
    }));
}

criterion_group!(benches, streebog512_benchmark, streebog256_benchmark);
criterion_main!(benches);

