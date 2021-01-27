use std::{cmp::Ordering, fs::File, io, io::BufReader, time::Duration};

use bstr::ByteSlice;
use bstr::io::BufReadExt;
use memmap::{Mmap, MmapOptions};
use packed_simd_2::u8x32;
use pbr::{ProgressBar, Units};

use crate::{collect::SavedHash, find::parse::PwnedHash, SHA1_BYTE_LENGTH};

mod advise;
mod parse;

const SIMD_WIDTH: usize = 32;

/// Pad the sha-1 hash to the full width of used SIMD instruction
type HashPadded = [u8; SIMD_WIDTH];

pub fn find_hash(hash_file: &File, hashes: &[SavedHash]) -> Result<(), io::Error> {
    if hashes.is_empty() {
        eprintln!("No stored passwords found");
        return Ok(());
    }

    match unsafe { MmapOptions::new().map(&hash_file) } {
        Ok(map) => {
            println!("Using memory maps - writes to the file or map could cause program crashes");
            find_hash_mapped(&map, hash_file, hashes)
        }
        Err(err) => {
            eprintln!("Failed to use memory maps using incremental search {}", err);
            find_hash_file_read(hash_file, hashes)
        }
    }
}

fn find_hash_mapped(map: &Mmap, hash_file: &File, hashes: &[SavedHash]) -> Result<(), io::Error> {
    // # Safety
    // It's unspecified if another process can modify the file or map and we see the changes.
    // This could cause unexpected changes for us and end up in a segmentation fault. Furthermore
    // mapping it to memory hides I/O errors from us. So we try at least to make the file
    // read only. Although other processes could overwrite it. Mandatory locking seems to be not
    // possible on all platforms: https://users.rust-lang.org/t/how-unsafe-is-mmap/19635/

    let did_change = hash_file.metadata().and_then(|metadata| {
        let mut permissions = metadata.permissions();
        if metadata.permissions().readonly() {
            Ok(false)
        } else {
            permissions.set_readonly(true);
            hash_file.set_permissions(permissions)?;
            Ok(true)
        }
    }).unwrap_or_else(|err| {
        eprintln!(
            "Failed to request read only for the hash database - \
            program could crash if there are concurrent modifications {}",
            err);
        // fallback that we didn't change anything
        false
    });

    #[cfg(unix)]
        {
            use crate::find::advise::MemoryAdvice;

            // Safety: unsafe cast to mutable - however madvise seems to not change any data
            let ptr = map.as_ptr() as *mut u8;
            let len = map.len();
            if let Err(err) = advise::madvise(ptr, len, MemoryAdvice::Sequential) {
                eprintln!("Failed to advise OS about memory usage - continuing without it {}", err);
            }
        }

    // blocking - help the compiler with the type
    let data: &[u8] = &map;
    let len = map.len() as u64;
    find_hash_incrementally(data, len, hashes)?;

    if did_change {
        let result = hash_file.metadata().map(|metadata| {
            let mut permissions = metadata.permissions();
            permissions.set_readonly(false);
            permissions
        }).and_then(|new_perm| hash_file.set_permissions(new_perm));

        if let Err(err) = result {
            eprintln!(
                "Failed to restore old readable state - please check the file yourself {}",
                err
            )
        }
    }

    Ok(())
}

fn find_hash_file_read(hash_file: &File, hashes: &[SavedHash]) -> Result<(), io::Error> {
    #[cfg(unix)]
        advise::fadvise(hash_file, 0, None, advise::FileAdvice::Sequential);

    let reader = BufReader::new(hash_file);
    let max_length = hash_file.metadata().map_or_else(|err| {
        eprintln!("Failed to fetch metadata {:?} - Using unlimited progress bar", err);
        0
    }, |metadata| metadata.len());

    find_hash_incrementally(reader, max_length, hashes)
}

fn find_hash_incrementally(hash_reader: impl BufReadExt, max_length: u64, hashes: &[SavedHash])
                           -> Result<(), io::Error> {
    // This effectively makes a copy - However we can expect that there are not many
    // saved passwords. The memory consumption from multiple copies would then be negligible
    let mut hashes = hashes.iter()
        .map(|x| {
            let mut hash_padded: HashPadded = [0; 32];
            hash_padded[..SHA1_BYTE_LENGTH].copy_from_slice(&x.password_hash);
            (u8x32::from_slice_unaligned(&hash_padded), x)
        });

    let mut bar = ProgressBar::new(max_length);
    bar.set_units(Units::Bytes);

    // limit refresh, because we call add very frequently
    bar.set_max_refresh_rate(Some(Duration::from_secs(1)));

    // Safety we validated that it's not empty in the first find hash method
    let mut current_saved = hashes.next().unwrap();

    // re-use hash buffer to reduce the number of allocations
    let mut record: PwnedHash = PwnedHash::default();
    hash_reader
        // reads line-by-line including re-use the allocation
        // so we don't need to convert it to UTF-8 or make an extra allocation
        .for_byte_line(|line| {
            bar.add(line.len() as u64);

            if let Err(err) = record.parse_new_hash(line) {
                // abort because then there are probably more errors
                eprintln!("Failed to parse hash {:?}", err);
                return Ok(false);
            }

            let candidate = u8x32::from_slice_unaligned(&record.hash_padded);

            // match candidate.
            loop {
                match candidate.lex_ord().cmp(&current_saved.0.lex_ord()) {
                    Ordering::Equal => {
                        // found an exact match - advance hay
                        match record.parse_count(line).as_ref() {
                            Ok(count) => {
                                println!(
                                    "Your password for the following account {} has been pwned {}x times",
                                    current_saved.1, count
                                );
                            }
                            Err(err) => {
                                eprintln!("Failed to parse count number in: {} - {:?}",
                                          line.to_str().unwrap_or(""), err);
                                println!("Your password has been pwned {}", current_saved.1);
                            }
                        }

                        match hashes.next() {
                            Some(next) => { current_saved = next; }
                            None => return Ok(false)
                        };
                    },
                    Ordering::Less => {
                        // x < than our current hay candidate - advance x
                        break;
                    }
                    Ordering::Greater => {
                        // x > than our current hay candidate - advance hay until it's higher again
                        // advance hay until it's higher again
                        match hashes.next() {
                            Some(next) => { current_saved = next; }
                            None => return Ok(false)
                        };
                    }
                }
            }

            Ok(true)
        })?;

    bar.finish();
    Ok(())
}
