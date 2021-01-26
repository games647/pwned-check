use std::{
    cmp::Ordering,
    collections::{BTreeSet, HashSet},
    hash::Hash,
};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fxhash::FxBuildHasher;
use indexmap::set::IndexSet;
use packed_simd_2::u8x32;
use rayon::prelude::*;

use common::Record;

mod common;

/// This benchmark doesn't evaluate the quality of the hashing implementations. However for our
/// input it seems enough.
///
/// https://github.com/tkaitchuck/aHash/blob/master/compare/readme.md#Speed

fn default_set_find(data: &[Record], hays: &HashSet<&Record>) -> usize {
    data.iter().filter(|&x| hays.contains(x)).count()
}

fn fx_set_find(data: &[Record], hays: &HashSet<&Record, FxBuildHasher>) -> usize {
    data.iter().filter(|&x| hays.contains(x)).count()
}

fn custom_fx_set_find(data: &[SimdHolder], hays: &HashSet<&SimdHolder, FxBuildHasher>) -> usize {
    data.iter().filter(|&x| hays.contains(x)).count()
}

fn tree_set_find(data: &[Record], hays: &BTreeSet<&Record>) -> usize {
    data.iter().filter(|&x| hays.contains(x)).count()
}

fn index_map_find_fx(data: &[Record], hays: &IndexSet<&Record, FxBuildHasher>) -> usize {
    data.iter().filter(|&x| hays.contains(x)).count()
}

fn array_find(data: &[Record], hays: &[Record]) -> usize {
    data.iter().filter(|&x| hays.contains(x)).count()
}

fn array_par_find(data: &[Record], hays: &[Record]) -> usize {
    data.par_iter().filter(|&x| hays.contains(x)).count()
}

fn array_simd_equal_find(data: &[Record], hays: &[Record]) -> usize {
    data.iter().filter(|&x| simd_contains(hays, x)).count()
}

fn array_par_simd_equal_find(data: &[Record], hays: &[Record]) -> usize {
    data.par_iter().filter(|&x| simd_contains(hays, x)).count()
}

fn simd_contains(hays: &[Record], x: &Record) -> bool {
    hays.iter().any(|h| {
        u8x32::from_slice_unaligned(x)
            .eq(u8x32::from_slice_unaligned(h))
            .all()
    })
}

fn array_simd_ordered_find(data: &[Record], hays: &[Record]) -> usize {
    let mut found = 0;

    let mut hays = hays.iter();
    let mut next = hays.next();
    for x in data {
        let packed_x = u8x32::from_slice_unaligned(&x[..]);

        loop {
            let current = match next {
                Some(inner) => inner,
                None => {
                    return found
                }
            };

            let mut packed_hay = u8x32::from_slice_unaligned(&current[..]);
            match packed_x.lex_ord().cmp(&packed_hay.lex_ord()) {
                Ordering::Equal => {
                    // found an exact match - advance hay
                    found += 1;
                    next = hays.next();
                    break;
                },
                Ordering::Less => {
                    // x < than our current hay candidate
                    // advance x
                    break;
                }
                Ordering::Greater => {
                    // x > than our current hay candidate
                    // advance hay until it's higher again
                    next = hays.next();
                }
            }
        }
    }

    found
}

/// Struct which uses 512 bit SIMD for identity comparisons
///
/// We disregard clippy here, because this structs only one field and eq is only our custom impl
/// of that comparison it doesn't have any effect on the equality
#[allow(clippy::derive_hash_xor_eq)]
#[derive(Eq, Hash)]
struct SimdHolder(Record);

impl PartialEq for SimdHolder {
    fn eq(&self, other: &Self) -> bool {
        let packed_self = u8x32::from_slice_unaligned(&self.0);
        let packed_other = u8x32::from_slice_unaligned(&other.0);
        packed_self.eq(packed_other).all()
    }
}

impl From<&Record> for SimdHolder {
    fn from(input: &Record) -> Self {
        SimdHolder(*input)
    }
}

fn find_benchmark(c: &mut Criterion) {
    const DATA_SIZE: usize = 100_000;
    const HAY_SIZE: usize = 256;

    let mut group = c.benchmark_group("find");

    let mut data_sorted = common::create_scrambled_data(DATA_SIZE);
    let mut max_hays = common::create_scrambled_data(HAY_SIZE);

    data_sorted.sort_unstable();

    max_hays.sort_unstable();

    let custom_data: Vec<SimdHolder> = data_sorted.iter().map(Into::into).collect();
    let custom_hay: Vec<SimdHolder> = max_hays.iter().map(Into::into).collect();

    for &hay_size in &[32, 64, 128, 256] {
        let sorted_hay = &sorted[..hay_size];
        let custom_h = &custom_hay[..hay_size];

        macro_rules! gen_bench {
            ($name:literal, $fut:ident) => {
                let id = BenchmarkId::new($name, hay_size);
                group.bench_with_input(id, &(&data_sorted, &sorted_hay), |b, (data, hays)| {
                    b.iter(|| $fut(data, &hays));
                });
            };
        }

        macro_rules! gen_bench_set {
            ($name:literal, $fut:ident) => {
                gen_bench_set!($name, $fut, data_sorted, sorted_hay);
            };
            ($name:literal, $fut:ident, $data:ident, $hays:ident) => {
                let id = BenchmarkId::new($name, hay_size);
                group.bench_with_input(id, &(&$data, &$hays), |b, (data, hays)| {
                    let set = hays.iter().collect();
                    b.iter(|| $fut(data, &set));
                });
            };
        }

        gen_bench!("Array", array_find);
        gen_bench!("Array (Parallel)", array_par_find);

        gen_bench!("Array (SIMD-Eq)", array_simd_equal_find);
        gen_bench!("Array (SIMD-Eq) (Parallel)", array_par_simd_equal_find);

        gen_bench_set!("Hashset", default_set_find);
        gen_bench_set!("Hashset (FX)", fx_set_find);
        gen_bench_set!(
            "Hashset (FX) (SIMD-Eq)",
            custom_fx_set_find,
            custom_data,
            custom_h
        );
        gen_bench_set!("BTreeSet", tree_set_find);
        gen_bench_set!("Indexmap (FX)", index_map_find_fx);

        let id = BenchmarkId::new("Array (SIMD-Ord)", hay_size);
        group.bench_with_input(id, &(&data_sorted, &sorted_hay), |b, (data, hays)| {
            b.iter(|| array_simd_ordered_find(data, &hays));
        });
    }

    // recommended but not necessary
    group.finish()
}

// generate main method
criterion_group!(benches, find_benchmark);
criterion_main!(benches);
