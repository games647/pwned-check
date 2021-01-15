#![feature(stdsimd)]

use std::convert::TryInto;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use init_with::InitWith;
use packed_simd_2::u8x32;
use rand::prelude::*;
use rayon::prelude::*;

fn normal_equal(data: &[[u8; 32]], hay: &[u8; 32]) -> bool {
    data.iter().any(|x| x.eq(hay))
}

fn normal_equal_threaded(data: &[[u8; 32]], hay: &[u8; 32]) -> bool {
    data.par_iter().any(|x| x.eq(hay))
}

fn simd_equal(data: &[[u8; 32]], hay: &[u8; 32]) -> bool {
    let hay = u8x32::from_slice_unaligned(hay);
    data.iter()
        .any(|x| u8x32::from_slice_unaligned(x).eq(hay).all())
}

fn simd_equal_threaded(data: &[[u8; 32]], hay: &[u8; 32]) -> bool {
    let hay = u8x32::from_slice_unaligned(hay);
    data.par_iter()
        .any(|x| u8x32::from_slice_unaligned(x).eq(hay).all())
}

fn create_scrambled_data(size: usize) -> Vec<[u8; 32]> {
    (0..size).map(|_| rand::thread_rng().gen()).collect()
}

fn simd_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("SIMD");

    let sizes = <[usize; 3]>::init_with_indices(|i| 10_usize.pow((i + 2).try_into().unwrap()));
    let data = create_scrambled_data(*sizes.last().unwrap());
    for &size in &sizes {
        let size_data = &data[0..size];
        let hay = rand::thread_rng().gen();

        let id = BenchmarkId::new("Normal", size);
        group.bench_with_input(id, &(size_data, hay), |b, (data, hay)| {
            b.iter(|| normal_equal(data, hay));
        });

        let id = BenchmarkId::new("Threaded", size);
        group.bench_with_input(id, &(size_data, hay), |b, (data, hay)| {
            b.iter(|| normal_equal_threaded(data, hay));
        });

        let id = BenchmarkId::new("SIMD", size);
        group.bench_with_input(id, &(size_data, hay), |b, (data, hay)| {
            b.iter(|| simd_equal(data, hay));
        });

        let id = BenchmarkId::new("SIMD-Threaded", size);
        group.bench_with_input(id, &(size_data, hay), |b, (data, hay)| {
            b.iter(|| simd_equal_threaded(data, hay));
        });
    }

    // recommended but not necessary
    group.finish()
}

// generate main method
criterion_group!(benches, simd_benchmark);
criterion_main!(benches);
