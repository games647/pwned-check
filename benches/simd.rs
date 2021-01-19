use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use packed_simd_2::u8x32;
use rand::prelude::*;
use rayon::prelude::*;

use common::Record;

mod common;

fn normal_equal(data: &[Record], hay: &Record) -> bool {
    data.iter().any(|x| x.eq(hay))
}

fn normal_equal_threaded(data: &[Record], hay: &Record) -> bool {
    data.par_iter().any(|x| x.eq(hay))
}

fn simd_equal(data: &[Record], hay: &Record) -> bool {
    let hay = u8x32::from_slice_unaligned(hay);
    data.iter()
        .any(|x| u8x32::from_slice_unaligned(x).eq(hay).all())
}

fn simd_equal_threaded(data: &[Record], hay: &Record) -> bool {
    let hay = u8x32::from_slice_unaligned(hay);
    data.par_iter()
        .any(|x| u8x32::from_slice_unaligned(x).eq(hay).all())
}

fn simd_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("SIMD");

    let sizes = common::SIZE_ARRAY;
    let data = common::create_scrambled_data(*sizes.last().unwrap());
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
