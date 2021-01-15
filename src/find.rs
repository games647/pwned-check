use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    fs::File,
    io::BufReader,
    num::ParseIntError,
};

use atoi::atoi;
use bstr::io::BufReadExt;
use data_encoding::HEXUPPER;

use crate::collect::SavedHash;
use crate::find::ParseHashError::*;

#[derive(Debug)]
struct PwnedHash {
    hash: Vec<u8>,
    count: u32,
}

#[derive(Debug)]
enum ParseHashError {
    IntError(),
    InvalidFormat(),
}

impl TryFrom<&[u8]> for PwnedHash {
    type Error = ParseHashError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        assert!(&[value[40]] == b":");

        let hash_part = &value[0..40];
        let hash = HEXUPPER.decode(&hash_part).unwrap();

        let count = atoi::<u32>(&value[41..]).ok_or(IntError())?;

        Ok(PwnedHash { hash, count })
    }
}

pub fn find_hash(hash_file: &File, hashes: &[SavedHash]) {
    // make a copy of this hash rather than below (at the get call), because it's more likely that
    // there are fewer saved passwords than in the database
    let map: HashMap<&[u8], &SavedHash> = hashes
        .iter()
        .map(|x| (x.password_hash.as_ref(), x))
        .collect();

    BufReader::new(hash_file)
        // reads line-by-line including re-use the allocation
        // so we don't need to convert it to UTF-8 or make an extra allocation
        .for_byte_line(|line| {
            let record: PwnedHash = line.try_into().unwrap();
            if let Some(saved) = map.get(record.hash.as_slice()) {
                let count = record.count;
                println!(
                    "Your password for the following account {} has been pwned {}x times",
                    saved, count
                );
            }

            Ok(true)
        })
        .unwrap();
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;

    use super::*;

    // demonstration of owned and borrowed variants
    mod owned {
        use super::*;

        // implementation where the record owns the String
        #[derive(Debug)]
        struct HashRecordOwned {
            hash: String,
            count: u32,
        }

        impl TryFrom<String> for HashRecordOwned {
            type Error = ParseHashError;

            fn try_from(mut value: String) -> Result<Self, Self::Error> {
                match value.find(':') {
                    None => Err(InvalidFormat()),
                    Some(index) => {
                        // extract first the count, because it would get dropped later
                        let count = value[index + 1..].parse()?;

                        value.truncate(index);
                        Ok(HashRecordOwned { hash: value, count })
                    }
                }
            }
        }

        // automatically convert ParseIntError in our custom enum type IntError
        impl From<ParseIntError> for ParseHashError {
            fn from(_: ParseIntError) -> Self {
                IntError()
            }
        }

        #[test]
        fn test_parse_owned() -> Result<(), ParseHashError> {
            let record: HashRecordOwned = {
                // here the owned String would get dropped - however it gets moved into the record
                let droppable = "000000005AD76BD555C1D6D771DE417A4B87E4B4:4".to_string();
                droppable.try_into()?
            };

            assert_eq!(record.hash, "000000005AD76BD555C1D6D771DE417A4B87E4B4");
            assert_eq!(record.count, 4);

            Ok(())
        }

        #[test]
        fn test_number_parse_owned_error() {
            let line = "000000005AD76BD555C1D6D771DE417A4B87E4B4:abc".to_string();
            let result: Result<HashRecordOwned, _> = line.try_into();
            assert_matches!(result, Err(IntError()));
        }
    }

    mod borrow {
        use super::*;

        // Use &str for the hash to prevent allocations that are not necessary
        // (borrow instead of owning). Using the lifetime parameter we make sure that as long this
        // records exist the owner of this string exists too. In this scenario this struct only
        // exists for a cleaner code.
        //
        // While reading the hash database (i.e. from file) into a bytes buffer on a per line basis,
        // we could re-use the same buffer for the hash string, because the hash is a view on a
        // range of those bytes. After comparing this record, we discard it. Therefore we no longer
        // borrow it and bytes buffer mutated to be filled with the next line.
        //
        // Using `String` would mean to perform a memory copy for each struct, so that it owns its
        // data. However then the bytes buffer and this struct could then be mutated independently.
        // They now have two different memory locations.
        #[derive(Debug)]
        struct PwnedHashBorrow<'a> {
            hash: &'a str,
            count: u32,
        }

        impl<'a> TryFrom<&'a str> for PwnedHashBorrow<'a> {
            type Error = ParseHashError;

            fn try_from(value: &'a str) -> Result<Self, Self::Error> {
                let mut comp = value.split(':');

                let hash = comp.next().ok_or_else(InvalidFormat)?;
                let count = comp.next().ok_or_else(InvalidFormat)?.parse()?;

                Ok(PwnedHashBorrow { hash, count })
            }
        }

        #[test]
        fn test_parse_borrow() -> Result<(), ParseHashError> {
            let record: PwnedHashBorrow<'_> =
                "000000005AD76BD555C1D6D771DE417A4B87E4B4:4".try_into()?;

            assert_eq!(record.hash, "000000005AD76BD555C1D6D771DE417A4B87E4B4");
            assert_eq!(record.count, 4);

            Ok(())
        }

        #[test]
        fn test_number_parse_error_borrow() {
            let line = "000000005AD76BD555C1D6D771DE417A4B87E4B4:abc";
            let result: Result<PwnedHashBorrow<'_>, _> = line.try_into();
            assert_matches!(result, Err(IntError()));
        }
    }

    #[test]
    fn test_parse() -> Result<(), ParseHashError> {
        let line: &[u8] = b"000000005AD76BD555C1D6D771DE417A4B87E4B4:4";
        let record: PwnedHash = line.try_into()?;

        assert_eq!(
            HEXUPPER.encode(&record.hash),
            "000000005AD76BD555C1D6D771DE417A4B87E4B4"
        );
        assert_eq!(record.count, 4);

        Ok(())
    }

    #[test]
    fn test_number_parse_error() {
        let line: &[u8] = b"000000005AD76BD555C1D6D771DE417A4B87E4B4:abc";

        let result: Result<PwnedHash, _> = line.try_into();
        assert_matches!(result, Err(IntError()));
    }
}
