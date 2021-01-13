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

#[cfg(target_feature = "avx")]
fn simd_equal(data: &[[u8; 32]], hay: &[u8; 32]) -> bool {
    let hay = u8x32::from_slice_unaligned(hay);
    data.iter()
        .any(|x| {
            let check = u8x32::from_slice_unaligned(x);
            check.eq(hay).all()
        })
}

fn create_scrambled_data(size: usize) -> Vec<[u8; 32]> {
    (0..size).map(|_| {
        let buf: [u8; 32] = rand::thread_rng().gen();
        buf
    }).collect()
}

fn simd_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("SIMD-Group");

    let sizes = <[usize; 3]>::init_with_indices(|i| 10_usize.pow((i + 2).try_into().unwrap()));
    let data = create_scrambled_data(*sizes.last().unwrap());
    for &size in &sizes {
        let size_data = &data[0..size];
        let hay = rand::thread_rng().gen();

        let id = BenchmarkId::new("Normal", size);
        group.bench_function(id, |b| {
            b.iter_with_large_drop(|| normal_equal(&size_data, hay));
        });

        let id = BenchmarkId::new("SIMD", size);
        group.bench_function(id, |b| {
            b.iter_with_large_drop(|| simd_equal(&size_data, hay));
        });
    }

    // recommended but not necessary
    group.finish()
}

// generate main method
criterion_group!(benches, simd_benchmark);
criterion_main!(benches);
