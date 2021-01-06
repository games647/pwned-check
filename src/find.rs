use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::num::ParseIntError;

use crate::find::ParseHashError::*;

// use rayon::prelude::*;

// Use &str for the hash to prevent allocations that are not necessary (borrow instead of owning).
// Using the lifetime parameter we make sure that as long this records exist the owner of this
// string exists too. In this scenario this struct only exists for a cleaner code.
//
// While reading the hash database (i.e. from file) into a bytes buffer on a per line basis,
// we could re-use the same buffer for the hash string, because the hash is a view on a range of
// those bytes. After comparing this record, we discard it. Therefore we no longer borrow it
// and bytes buffer mutated to be filled with the next line.
//
// Using `String` would mean to perform a memory copy for each struct, so that it owns its data.
// However then the bytes buffer and this struct could then be mutated independently. They now have
// two different memory locations.
#[derive(Debug)]
struct HashRecord<'a> {
    hash: &'a str,
    count: u32,
}

#[derive(Debug)]
enum ParseHashError {
    IntError(ParseIntError),
    InvalidFormat(),
}

// automatically convert ParseIntError in our custom enum type IntError
impl From<ParseIntError> for ParseHashError {
    fn from(e: ParseIntError) -> Self {
        IntError(e)
    }
}

impl<'a> TryFrom<&'a str> for HashRecord<'a> {
    type Error = ParseHashError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let mut comp = value.split(':');

        // do not create default if not necessary
        let hash = comp.next().ok_or_else(InvalidFormat)?;
        let count = comp.next().ok_or_else(InvalidFormat)?.parse()?;

        // Ok(HashRecord { hash, count })
        Ok(HashRecord { hash, count })
    }
}

pub fn find_hash(hash_file: &File) {
    let reader = BufReader::new(hash_file);
    for line in reader.lines() {
        let line = line.unwrap();
        let record: Result<HashRecord<'_>, _> = line.as_str().try_into();
        println!("{:?}", record);
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryInto;

    use assert_matches::assert_matches;

    use super::*;

    #[test]
    fn test_parse() -> Result<(), ParseHashError> {
        let record: HashRecord<'_> = "000000005AD76BD555C1D6D771DE417A4B87E4B4:4".try_into()?;
        assert_eq!(record.hash, "000000005AD76BD555C1D6D771DE417A4B87E4B4");
        assert_eq!(record.count, 4);

        Ok(())
    }

    #[test]
    fn test_number_parse_error() {
        let line = "000000005AD76BD555C1D6D771DE417A4B87E4B4:abc";
        let result: Result<HashRecord<'_>, _> = line.try_into();
        assert_matches!(result, Err(IntError(_)));
    }
}
