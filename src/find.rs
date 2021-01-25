use std::{
    collections::HashMap, fs::File, io::BufReader,
    time::Duration,
};

use bstr::io::BufReadExt;
use fxhash::FxBuildHasher;
use memmap::{Mmap, MmapOptions};
use pbr::{ProgressBar, Units};

use crate::{
    collect::SavedHash,
    find::parse::PwnedHash,
    Sha1Hash,
};

mod parse;
mod advise;

pub fn find_hash(hash_file: &File, hashes: &[SavedHash]) {
    let mmap = unsafe { MmapOptions::new().map(&hash_file) };
    match mmap {
        Ok(map) => {
            println!("Using memory maps - writes to the file or map could cause program crashes");
            find_hash_mapped(&map, hash_file, hashes);
        }
        Err(err) => {
            eprintln!("Failed to use memory maps using incremental search {}", err);
            find_hash_file_read(hash_file, hashes);
        }
    }
}

fn find_hash_mapped(map: &Mmap, hash_file: &File, hashes: &[SavedHash]) {
    // # Safety
    // It's unspecified if another process can modify the file or map and we see the changes.
    // This could cause unexpected changes for us and end up in a segmentation fault. Furthermore
    // mapping it to memory hides I/O errors from us. So we try at least to make the file
    // read only. Although other processes could overwrite it. Mandatory locking seems to be not
    // possible on all platforms: https://users.rust-lang.org/t/how-unsafe-is-mmap/19635/

    let mut perms = hash_file.metadata().unwrap().permissions();
    let was_read_only = perms.readonly();
    perms.set_readonly(true);
    hash_file.set_permissions(perms).unwrap();

    #[cfg(unix)]
        {
            let ptr = map.as_ptr() as *mut ();
            advise::madvise(ptr, map.len(), advise::MemoryAdvice::Sequential).unwrap();
        }

    // blocking - help the compiler with the type
    let data: &[u8] = &map;
    find_hash_incrementally(data, map.len() as u64, hashes);

    if was_read_only {
        let mut perms = hash_file.metadata().unwrap().permissions();
        perms.set_readonly(false);
        hash_file.set_permissions(perms).unwrap();
    }
}

fn find_hash_file_read(hash_file: &File, hashes: &[SavedHash]) {
    #[cfg(unix)]
        advise::fadvise(hash_file, 0, None, advise::FileAdvice::Sequential);

    let reader = BufReader::new(hash_file);
    let max_length = hash_file.metadata().unwrap().len();
    find_hash_incrementally(reader, max_length, hashes);
}

fn find_hash_incrementally(hash_reader: impl BufReadExt, max_length: u64, hashes: &[SavedHash]) {
    // make a copy of this hash rather than below (at the get call), because it's more likely that
    // there are fewer saved passwords than in the database
    let map: HashMap<&Sha1Hash, &SavedHash, FxBuildHasher> =
        hashes.iter().map(|x| (&x.password_hash, x)).collect();

    let mut bar = ProgressBar::new(max_length);
    bar.set_units(Units::Bytes);

    // limit, because we call add very frequently
    bar.set_max_refresh_rate(Some(Duration::from_secs(1)));

    // re-use hash buffer to reduce the number of allocations
    let mut record: PwnedHash = PwnedHash::default();

    hash_reader
        // reads line-by-line including re-use the allocation
        // so we don't need to convert it to UTF-8 or make an extra allocation
        .for_byte_line(|line| {
            bar.add(line.len() as u64);

            record.parse_new_hash(line).unwrap();
            if let Some(saved) = map.get(&record.hash) {
                let count = record.parse_count(line).as_ref().unwrap();
                println!(
                    "Your password for the following account {} has been pwned {}x times",
                    saved, count
                );
            }

            Ok(true)
        })
        .unwrap();

    bar.finish();
}
