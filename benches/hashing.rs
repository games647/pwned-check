use std::convert::TryInto;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use crossbeam_channel::{bounded, Receiver};
use crossbeam_utils::thread;
use data_encoding::HEXUPPER;
use init_with::InitWith;
use rand::{distributions::Alphanumeric, prelude::*};
use rayon::prelude::*;
use ring::digest::{digest, Digest, SHA1_FOR_LEGACY_USE_ONLY};

/// sequential hashing of bytes to the hex string representation
fn hash_sequential(data: &[[u8; 32]]) -> Vec<String> {
    data.iter().map(|x| hash_string(x)).collect()
}

/// hash sequential, but keep the byte representation
fn hash_bytes_sequential(data: &[[u8; 32]]) -> Vec<Digest> {
    data.iter().map(|x| hash_func(x)).collect()
}

/// parallel hashing with hex representation
fn hash_threaded(data: &[[u8; 32]]) -> Vec<String> {
    data.par_iter().map(|x| hash_string(x)).collect()
}

/// parallel hashing but keeping the byte representation
fn hash_bytes_threaded(data: &[[u8; 32]]) -> Vec<Digest> {
    data.par_iter().map(|x| hash_func(x)).collect()
}

/// parallel hashing but keeping the byte representation
fn hash_bytes_channel(data: &[[u8; 32]]) -> Vec<Digest> {
    // data channel (function data) with input (send) and output (rec)
    let size = data.len();
    let (data_send, data_rec) = bounded(size);
    let (hash_send, hash_rec) = bounded(size);

    // end is exclusive so start with 0
    thread::scope(|scope| {
        for _ in 0..num_cpus::get() {
            let local_data_rec: Receiver<&[u8; 32]> = data_rec.clone();
            let local_hash_send = hash_send.clone();
            scope.spawn(move |_| {
                for input in local_data_rec {
                    local_hash_send.send(hash_func(input)).unwrap();
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
    })
        .unwrap()
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
fn create_scrambled_data(size: usize) -> Vec<[u8; 32]> {
    (0..size)
        .map(|_| {
            let mut buf: [u8; 32] = [0; 32];
            for x in buf.iter_mut() {
                *x = rand::thread_rng().sample(&Alphanumeric);
            }

            buf
        })
        .collect()
}

fn hashing_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hashing");

    let sizes = <[usize; 3]>::init_with_indices(|i| 10_usize.pow((i + 2).try_into().unwrap()));
    let data = create_scrambled_data(*sizes.last().unwrap());
    for &size in &sizes {
        let size_data = &data[0..size];

        /// Generates benchmark test units
        ///
        /// # Examples
        ///
        /// ```
        /// gen_bench!("Test-Method", method_name);
        /// ```
        macro_rules! gen_bench {
            // representation name and function under test
            ($name:literal, $fut:ident) => {
                let id = BenchmarkId::new($name, size);
                group.bench_with_input(id, size_data, |b, input| {
                    b.iter_with_large_drop(|| $fut(input));
                });
            };
        }

        gen_bench!("Sequential", hash_sequential);
        gen_bench!("Sequential-Bytes", hash_bytes_sequential);
        gen_bench!("Threaded", hash_threaded);
        gen_bench!("Threaded-Bytes", hash_bytes_threaded);
        gen_bench!("Threaded-Channel-Bytes", hash_bytes_channel);
    }

    // recommended but not necessary
    group.finish()
}

// generate main method
criterion_group!(benches, hashing_benchmark);
criterion_main!(benches);
