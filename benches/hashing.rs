use std::convert::TryInto;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use crossbeam_channel::{bounded, Receiver, Sender};
use crossbeam_utils::thread;
use data_encoding::HEXUPPER;
use init_with::InitWith;
use rand::{
    distributions::Alphanumeric,
    prelude::*,
};
use rayon::prelude::*;
use ring::digest::{digest, Digest, SHA1_FOR_LEGACY_USE_ONLY};

/// sequential hashing of bytes to the hex string representation
fn hash_sequential(data: &[Vec<u8>]) -> Vec<String> {
    data.iter().map(|x| hash_string(x)).collect()
}

/// hash sequential, but keep the byte representation
fn hash_bytes_sequential(data: &[Vec<u8>]) -> Vec<Digest> {
    data.iter().map(|x| hash_func(x)).collect()
}

/// parallel hashing with hex representation
fn hash_threaded(data: &[Vec<u8>]) -> Vec<String> {
    data.par_iter().map(|x| hash_string(x)).collect()
}

/// parallel hashing but keeping the byte representation
fn hash_bytes_threaded(data: &[Vec<u8>]) -> Vec<Digest> {
    data.par_iter().map(|x| hash_func(x)).collect()
}

/// parallel hashing but keeping the byte representation
fn hash_bytes_channel(data: &[Vec<u8>]) -> Vec<Digest> {
    // data channel (function data) with input (send) and output (rec)
    let size = data.len();
    let (data_send, data_rec): (Sender<&Vec<u8>>, Receiver<&Vec<u8>>) = bounded(size);
    let (hash_send, hash_rec): (Sender<Digest>, Receiver<Digest>) = bounded(size);

    // end is exclusive so start with 0
    thread::scope(|scope| {
        for _ in 0..num_cpus::get() {
            let local_data_rec = data_rec.clone();
            let local_hash_send = hash_send.clone();
            scope.spawn(move |_| {
                for input in local_data_rec {
                    local_hash_send.send(hash_func(&input)).unwrap();
                }

                // drop it explicitly so we could notice the done signal
                drop(local_hash_send);
            });
        }

        for record in data {
            data_send.send(record).unwrap();
        }

        // drop the original sender - we could notice the disconnect
        drop(hash_send);
        drop(data_send);

        hash_rec.iter().collect()
    }).unwrap()
}

/// hash and format to the hex representation
fn hash_string(x: &[u8]) -> String {
    HEXUPPER.encode(hash_func(x).as_ref())
}

/// hashing function under test
fn hash_func(x: &[u8]) -> Digest {
    digest(&SHA1_FOR_LEGACY_USE_ONLY, x)
}

/// create random bytes of data with each exactly 32 characters in size
fn create_scrambled_data(size: usize) -> Vec<Vec<u8>> {
    (0..size)
        .map(|_| {
            rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .collect()
        })
        .collect()
}

fn hashing_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hashing");

    let sizes = <[usize; 3]>::init_with_indices(|i| 10_usize.pow((i + 2).try_into().unwrap()));
    let data = create_scrambled_data(*sizes.last().unwrap());
    for &size in &sizes {
        let size_data = &data[0..size];

        let id = BenchmarkId::new("Sequential", size);
        group.bench_with_input(id, size_data, |b, input| {
            b.iter_with_large_drop(|| hash_sequential(input));
        });

        let id = BenchmarkId::new("Sequential-Bytes", size);
        group.bench_with_input(id, size_data, |b, input| {
            b.iter_with_large_drop(|| hash_bytes_sequential(input));
        });

        let id = BenchmarkId::new("Threaded", size);
        group.bench_with_input(id, size_data, |b, input| {
            b.iter_with_large_drop(|| hash_threaded(input));
        });

        let id = BenchmarkId::new("Threaded-Bytes", size);
        group.bench_with_input(id, size_data, |b, input| {
            b.iter_with_large_drop(|| hash_bytes_threaded(input));
        });

        let id = BenchmarkId::new("Threaded-Channel-Bytes", size);
        group.bench_with_input(id, size_data, |b, input| {
            b.iter_with_large_drop(|| hash_bytes_channel(input));
        });
    }

    // recommended but not necessary
    group.finish()
}

// generate main method
criterion_group!(benches, hashing_benchmark);
criterion_main!(benches);
