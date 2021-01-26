use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use crossbeam_channel::{bounded, Receiver};
use crossbeam_utils::thread;
use data_encoding::HEXUPPER;
use rand::{distributions::Alphanumeric, prelude::*};
use rayon::prelude::*;
use ring::digest::{digest, Digest, SHA1_FOR_LEGACY_USE_ONLY};

use common::Record;

mod common;

/// sequential hashing of bytes to the hex string representation
fn hash_sequential(data: &[Record]) -> Vec<String> {
    data.iter()
        .map(|x| hash_func(x))
        .map(|x| hex_encode(&x))
        .collect()
}

/// hash sequential, but keep the byte representation
fn hash_bytes_sequential(data: &[Record]) -> Vec<Digest> {
    data.iter().map(|x| hash_func(x)).collect()
}

/// parallel hashing with hex representation
fn hash_threaded(data: &[Record]) -> Vec<String> {
    data.par_iter()
        .map(|x| hash_func(x))
        .map(|x| hex_encode(&x))
        .collect()
}

/// parallel hashing but keeping the byte representation
fn hash_bytes_threaded(data: &[Record]) -> Vec<Digest> {
    data.par_iter().map(|x| hash_func(x)).collect()
}

/// parallel hashing but keeping the byte representation
fn hash_bytes_channel(data: &[Record]) -> Vec<Digest> {
    // data channel (function data) with input (send) and output (rec)
    let size = data.len();
    let (data_send, data_rec) = bounded(size);
    let (hash_send, hash_rec) = bounded(size);

    // end is exclusive so start with 0
    thread::scope(|scope| {
        for _ in 0..num_cpus::get() {
            let local_data_rec: Receiver<&Record> = data_rec.clone();
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
fn hex_encode(hash_result: &Digest) -> String {
    HEXUPPER.encode(hash_result.as_ref())
}

/// hashing function under test
fn hash_func(input_bytes: &[u8]) -> Digest {
    digest(&SHA1_FOR_LEGACY_USE_ONLY, input_bytes)
}

/// create random bytes of data with each exactly 32 characters in size
fn create_scrambled_data(size: usize) -> Vec<Record> {
    (0..size)
        .map(|_| {
            let mut buf: Record = [0; common::RECORD_BYTE_SIZE];
            for x in buf.iter_mut() {
                *x = rand::thread_rng().sample(&Alphanumeric);
            }

            buf
        })
        .collect()
}

fn hashing_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hashing");

    let sizes = common::SIZE_ARRAY;
    let data = create_scrambled_data(*sizes.last().unwrap());
    for &size in &sizes {
        let size_data = &data[..size];

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
