#![feature(stdsimd)]

use std::convert::TryInto;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use init_with::InitWith;
use packed_simd_2::u8x32;
use rand::prelude::*;
use rayon::prelude::*;

/// 32 * byte fits perfects into 256bit SIMD lane width which is more wide spread
const COMPARE_BYTE_SIZE: usize = 32;

fn normal_equal(data: &[[u8; COMPARE_BYTE_SIZE]], hay: &[u8; COMPARE_BYTE_SIZE]) -> bool {
    data.iter().any(|x| x.eq(hay))
}

fn normal_equal_threaded(data: &[[u8; COMPARE_BYTE_SIZE]], hay: &[u8; COMPARE_BYTE_SIZE]) -> bool {
    data.par_iter().any(|x| x.eq(hay))
}

fn simd_equal(data: &[[u8; COMPARE_BYTE_SIZE]], hay: &[u8; COMPARE_BYTE_SIZE]) -> bool {
    let hay = u8x32::from_slice_unaligned(hay);
    data.iter()
        .any(|x| u8x32::from_slice_unaligned(x).eq(hay).all())
}

fn simd_equal_threaded(data: &[[u8; COMPARE_BYTE_SIZE]], hay: &[u8; COMPARE_BYTE_SIZE]) -> bool {
    let hay = u8x32::from_slice_unaligned(hay);
    data.par_iter()
        .any(|x| u8x32::from_slice_unaligned(x).eq(hay).all())
}

fn create_scrambled_data(size: usize) -> Vec<[u8; COMPARE_BYTE_SIZE]> {
    (0..size).map(|_| rand::thread_rng().gen()).collect()
}

fn simd_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("SIMD");

    let sizes = <[usize; 3]>::init_with_indices(|i| 10_usize.pow((i + 2).try_into().unwrap()));
    let data = create_scrambled_data(*sizes.last().unwrap());
    for &size in &sizes {
        let size_data = &data[0..size];

        // random hay, because otherwise Rust could perhaps optimize it to memory address compare
        let hay = rand::thread_rng().gen();

        /// Generates benchmark test units
        ///
        /// # Examples
        ///
        /// ```
        /// gen_bench!("Test-Method", method_name);
        /// ```
        macro_rules! gen_bench {
            ($name:literal, $fut:ident) => {
                let id = BenchmarkId::new($name, size);
                group.bench_with_input(id, &(size_data, hay), |b, (data, hay)| {
                    b.iter(|| $fut(data, hay));
                });
            };
        }

        gen_bench!("Normal", normal_equal);
        gen_bench!("Threaded", normal_equal_threaded);
        gen_bench!("SIMD", simd_equal);
        gen_bench!("SIMD-Threaded", simd_equal_threaded);
    }

    // recommended but not necessary
    group.finish()
}

// generate main method
criterion_group!(benches, simd_benchmark);
criterion_main!(benches);
