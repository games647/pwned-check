use std::iter;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::{distributions::Alphanumeric, prelude::*};
use ring::digest::{digest, Digest, SHA1_FOR_LEGACY_USE_ONLY};

mod common;

fn expensive_fn(data: &[u8]) -> Digest {
    digest(&SHA1_FOR_LEGACY_USE_ONLY, data)
}

mod borrow {
    use ring::digest::Digest;

    use crate::expensive_fn;

    pub fn fut(input: &[&str]) -> Vec<Digest> {
        input.iter().map(|&x| expensive_fn(x.as_bytes())).collect()
    }
}

mod owned {
    use rayon::prelude::*;
    use ring::digest::Digest;

    use crate::expensive_fn;

    struct OwnedData(String);

    pub fn fut(input: &[&str]) -> Vec<Digest> {
        input
            .iter()
            .map(|&x| {
                // explicit clone due to the to_string call
                let data = OwnedData(x.to_string());
                expensive_fn(data.0.as_bytes())
            })
            .collect()
    }

    pub fn fut_threaded(input: &[&str]) -> Vec<Digest> {
        // explicitly collect into it's own vec to simulate single threaded reading
        let mapped: Vec<OwnedData> = input
            .iter()
            .map(ToString::to_string)
            .map(OwnedData)
            .collect();

        mapped
            .par_iter()
            .map(|x| expensive_fn(x.0.as_bytes()))
            .collect()
    }
}

fn create_scrambled_data(size: usize) -> Vec<String> {
    (0..size)
        .map(|_| {
            iter::repeat(())
                .map(|_| rand::thread_rng().sample(&Alphanumeric))
                .map(char::from)
                .take(common::RECORD_BYTE_SIZE)
                .collect()
        })
        .collect()
}

fn memory_benchmark(c: &mut Criterion) {
    const SIZE: usize = 1_000_000;

    let mut group = c.benchmark_group("Memory");
    let data = create_scrambled_data(SIZE);

    let data: Vec<&str> = data.iter().map(String::as_str).collect();

    group.bench_with_input("Borrow", &data, |b, data| {
        b.iter_with_large_drop(|| borrow::fut(data));
    });

    group.bench_with_input("Owned", &data, |b, data| {
        b.iter_with_large_drop(|| owned::fut(data));
    });

    for threads in (2..=num_cpus::get()).step_by(2) {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();

        let id = BenchmarkId::new("Owned (Threaded)", threads);
        group.bench_with_input(id, &data, |b, data| {
            b.iter_with_large_drop(|| pool.install(|| owned::fut_threaded(data)));
        });
    }

    // recommended but not necessary
    group.finish()
}

// generate main method
criterion_group!(benches, memory_benchmark);
criterion_main!(benches);
