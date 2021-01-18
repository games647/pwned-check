/// This benchmark doesn't evaluate the quality of the hashing implementations. However for our
/// input it seems enough.
///
/// https://github.com/tkaitchuck/aHash/blob/master/compare/readme.md#Speed
use std::collections::{BTreeSet, HashSet};
use std::hash::{Hash, Hasher};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fxhash::FxBuildHasher;
use indexmap::set::IndexSet;
use packed_simd_2::u8x32;
use rand::prelude::*;
use rayon::prelude::*;

const RECORD_BYTE_SIZE: usize = 32;

fn default_set_find(
    data: &[[u8; RECORD_BYTE_SIZE]],
    hays: &HashSet<&[u8; RECORD_BYTE_SIZE]>,
) -> usize {
    data.iter().filter(|x| hays.contains(*x)).count()
}

fn fx_set_find(
    data: &[[u8; RECORD_BYTE_SIZE]],
    hays: &HashSet<&[u8; RECORD_BYTE_SIZE], FxBuildHasher>,
) -> usize {
    data.iter().filter(|x| hays.contains(*x)).count()
}

fn custom_fx_set_find(data: &[SimdHolder], hays: &HashSet<&SimdHolder, FxBuildHasher>) -> usize {
    data.iter().filter(|x| hays.contains(*x)).count()
}

fn tree_set_find(
    data: &[[u8; RECORD_BYTE_SIZE]],
    hays: &BTreeSet<&[u8; RECORD_BYTE_SIZE]>,
) -> usize {
    data.iter().filter(|x| hays.contains(*x)).count()
}

fn index_map_find_fx(
    data: &[[u8; RECORD_BYTE_SIZE]],
    hays: &IndexSet<&[u8; RECORD_BYTE_SIZE], FxBuildHasher>,
) -> usize {
    data.iter().filter(|x| hays.contains(*x)).count()
}

fn array_find(data: &[[u8; RECORD_BYTE_SIZE]], hays: &[[u8; RECORD_BYTE_SIZE]]) -> usize {
    data.iter().filter(|x| hays.contains(*x)).count()
}

fn array_par_find(data: &[[u8; RECORD_BYTE_SIZE]], hays: &[[u8; RECORD_BYTE_SIZE]]) -> usize {
    data.par_iter().filter(|x| hays.contains(*x)).count()
}

fn array_simd_equal_find(
    data: &[[u8; RECORD_BYTE_SIZE]],
    hays: &[[u8; RECORD_BYTE_SIZE]],
) -> usize {
    data.iter()
        .filter(|x| {
            hays.iter().any(|h| {
                u8x32::from_slice_unaligned(&x[0..])
                    .eq(u8x32::from_slice_unaligned(h))
                    .all()
            })
        })
        .count()
}

fn array_par_simd_equal_find(
    data: &[[u8; RECORD_BYTE_SIZE]],
    hays: &[[u8; RECORD_BYTE_SIZE]],
) -> usize {
    data.par_iter()
        .filter(|x| {
            hays.iter().any(|h| {
                u8x32::from_slice_unaligned(&x[0..])
                    .eq(u8x32::from_slice_unaligned(h))
                    .all()
            })
        })
        .count()
}

fn array_simd_ordered_find(
    data: &[[u8; RECORD_BYTE_SIZE]],
    hays: &[[u8; RECORD_BYTE_SIZE]],
) -> usize {
    let max = hays.len();
    let mut count = 0;

    let mut current = hays[count];
    for x in data {
        let packed_x = u8x32::from_slice_unaligned(&x[0..]);
        let packed_hay = u8x32::from_slice_unaligned(&current);

        let m = packed_x.lt(packed_hay);
        if m.any() {
            continue;
        }

        let m = packed_x.eq(packed_hay);
        if m.all() {
            count += 1;
            if count == max {
                break;
            }

            current = hays[count];
        }
    }

    count
}

fn create_scrambled_data(size: usize) -> Vec<[u8; RECORD_BYTE_SIZE]> {
    (0..size).map(|_| rand::thread_rng().gen()).collect()
}

/// Struct which uses 512 bit SIMD for identity comparisons
struct SimdHolder {
    data: [u8; 32],
}

impl Eq for SimdHolder {}

impl PartialEq for SimdHolder {
    fn eq(&self, other: &Self) -> bool {
        let packed_self = u8x32::from_slice_unaligned(&self.data);
        let packed_other = u8x32::from_slice_unaligned(&other.data);
        packed_self.eq(packed_other).all()
    }
}

impl Hash for SimdHolder {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state);
    }
}

fn find_benchmark(c: &mut Criterion) {
    const DATA_SIZE: usize = 100_000;

    let mut group = c.benchmark_group("find");

    let data = create_scrambled_data(DATA_SIZE);
    let hays_max = create_scrambled_data(256);
    let mut sorted = hays_max.clone();
    sorted.sort_unstable();

    let custom_data: Vec<SimdHolder> = data.iter().map(|x| SimdHolder { data: *x }).collect();
    let custom_hay: Vec<SimdHolder> = hays_max.iter().map(|x| SimdHolder { data: *x }).collect();

    for &hay_size in &[32, 64, 128, 256] {
        let hays = &hays_max[..hay_size];
        let sorted = &sorted[..hay_size];
        let custom_h = &custom_hay[..hay_size];

        macro_rules! gen_bench {
            ($name:literal, $fut:ident) => {
                let id = BenchmarkId::new($name, hay_size);
                group.bench_with_input(id, &(&data, &hays), |b, (data, hays)| {
                    b.iter(|| $fut(data, &hays));
                });
            };
        }

        macro_rules! gen_bench_set {
            ($name:literal, $fut:ident) => {
                gen_bench_set!($name, $fut, data, hays);
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
        group.bench_with_input(id, &(&data, &sorted), |b, (data, hays)| {
            b.iter(|| array_simd_ordered_find(data, &hays));
        });
    }

    // recommended but not necessary
    group.finish()
}

// generate main method
criterion_group!(benches, find_benchmark);
criterion_main!(benches);
