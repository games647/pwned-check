use std::fs::File;
use std::io::{BufRead, BufReader};
use std::num::ParseIntError;
use std::str::FromStr;

use crate::find::ParseHashError::*;

// use rayon::prelude::*;

#[derive(Debug)]
struct HashRecord {
    hash: String,
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

impl FromStr for HashRecord {
    type Err = ParseHashError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let comp: Vec<&str> = input.split(':').collect();

        // do not create default if not necessary
        let hash = comp.get(0).map(|s| s.to_string()).ok_or_else(|| InvalidFormat())?;
        let count = comp.get(1).ok_or_else(|| InvalidFormat())?.parse()?;

        Ok(HashRecord { hash, count })
    }
}

pub fn find_hash(hash_file: &File) {
    let reader = BufReader::new(hash_file);
    let v: Vec<HashRecord> = reader
        .lines()
        .map(|l| l.unwrap().parse().unwrap())
        .into_iter()
        .collect();

    for line in v {
        println!("{:?}", line);
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;

    use super::*;

    #[test]
    fn test_parse() -> Result<(), ParseHashError> {
        let record: HashRecord = "000000005AD76BD555C1D6D771DE417A4B87E4B4:4".parse()?;
        assert_eq!(record.hash, "000000005AD76BD555C1D6D771DE417A4B87E4B4");
        assert_eq!(record.count, 4);

        Ok(())
    }

    #[test]
    fn test_number_parse_error() {
        let result: Result<HashRecord, _> = "000000005AD76BD555C1D6D771DE417A4B87E4B4:abc".parse();
        assert_matches!(result, Err(IntError(_)));
    }
}
