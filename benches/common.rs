use rand::prelude::*;

/// 32 * byte fits perfects into 256bit SIMD lane width which is more wide spread across users
pub const RECORD_BYTE_SIZE: usize = 32;

pub type Record = [u8; RECORD_BYTE_SIZE];

#[allow(dead_code)]
pub fn create_scrambled_data(size: usize) -> Vec<Record> {
    (0..size)
        .map(|_| {
            // According to the wiki filling bytes is faster than the gen method
            let mut buf = [0; RECORD_BYTE_SIZE];
            rand::thread_rng().fill_bytes(&mut buf);
            buf
        })
        .collect()
}

#[allow(dead_code)]
pub const SIZE_ARRAY: [usize; 3] = [100, 1_000, 10_000];
