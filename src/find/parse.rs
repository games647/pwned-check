use std::convert::TryFrom;
use std::num::ParseIntError;

use data_encoding::HEXUPPER;

use crate::{SHA1_BYTE_LENGTH, Sha1Hash};
use crate::find::parse::ParseHashError::{IntError, InvalidFormat};

#[derive(Debug, Default)]
pub struct PwnedHash {
    pub hash: Sha1Hash,
    // lazy load, because we only need it on an equal hit
    pub count: Option<Result<u32, ParseHashError>>,
}

impl TryFrom<&[u8]> for PwnedHash {
    type Error = ParseHashError;

    fn try_from(line: &[u8]) -> Result<Self, Self::Error> {
        let mut record = PwnedHash::default();
        record.parse_new_hash(line)?;
        record.parse_count(line);
        Ok(record)
    }
}

impl PwnedHash {
    pub fn parse_new_hash(&mut self, line: &[u8]) -> Result<(), ParseHashError> {
        assert!(&[line[40]] == b":");

        let hash_part = &line[..40];
        let len = HEXUPPER
            .decode_mut(hash_part, &mut self.hash)
            .map_err(|_| InvalidFormat())?;
        // verify that the length is not less
        assert_eq!(len, SHA1_BYTE_LENGTH);

        // reset count number if did before
        self.count = None;
        Ok(())
    }

    pub fn parse_count(&mut self, line: &[u8]) -> &Result<u32, ParseHashError> {
        // this has the performance penalty of converting to UTF-8 instead of using ASCII bytes
        // directly. However we likely don't call this method often, so it's negligible
        // otherwise we could use the atoi crate
        let count_part = &line[41..];
        let res = std::str::from_utf8(&count_part)
            .map_err(|_| InvalidFormat())
            // use Ok(..?) to make use of the automatic error convert instead of map_err
            .and_then(|s| Ok(s.parse()?));

        self.count = Some(res);
        self.count.as_ref().unwrap()
    }
}

#[derive(Debug)]
pub enum ParseHashError {
    IntError(ParseIntError),
    InvalidFormat(),
}

// automatically convert ParseIntError in our custom enum type IntError
impl From<ParseIntError> for ParseHashError {
    fn from(e: ParseIntError) -> Self {
        IntError(e)
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryInto;

    use assert_matches::assert_matches;
    use data_encoding::HEXUPPER;

    use crate::SHA1_BYTE_LENGTH;

    use super::*;

    const TEST_LINE: &str = "000000005AD76BD555C1D6D771DE417A4B87E4B4:4";
    const INVALID_INT: &str = "000000005AD76BD555C1D6D771DE417A4B87E4B4:abc";

    // demonstration of owned and borrowed variants
    mod owned {
        use std::convert::TryInto;

        use crate::find::parse::ParseHashError::InvalidFormat;

        use super::*;

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

        #[test]
        fn test_parse_owned() {
            let record: HashRecordOwned = {
                // here the owned String would get dropped - however it gets moved into the record
                let droppable = TEST_LINE.to_string();
                droppable.try_into().unwrap()
            };

            assert_eq!(record.hash, "000000005AD76BD555C1D6D771DE417A4B87E4B4");
            assert_eq!(record.count, 4);
        }

        #[test]
        fn test_number_parse_owned_error() {
            let result: Result<HashRecordOwned, _> = INVALID_INT.to_string().try_into();
            assert_matches!(result, Err(IntError(_)));
        }
    }

    mod borrow {
        use std::convert::TryInto;

        use crate::find::parse::ParseHashError::InvalidFormat;

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
        fn test_parse_borrow() {
            let record: PwnedHashBorrow<'_> = TEST_LINE.try_into().unwrap();
            assert_eq!(record.hash, "000000005AD76BD555C1D6D771DE417A4B87E4B4");
            assert_eq!(record.count, 4);
        }

        #[test]
        fn test_number_parse_error_borrow() {
            let result: Result<PwnedHashBorrow<'_>, _> = INVALID_INT.try_into();
            assert_matches!(result, Err(IntError(_)));
        }
    }

    #[test]
    fn test_parse() {
        let bytes_line = TEST_LINE.as_bytes();
        let record: PwnedHash = bytes_line.try_into().unwrap();
        assert_matches!(record.count.unwrap(), Ok(4));
        assert_eq!(
            HEXUPPER.encode(&record.hash),
            "000000005AD76BD555C1D6D771DE417A4B87E4B4"
        );
    }

    #[test]
    fn test_overriding() {
        let mut record: PwnedHash = PwnedHash {
            hash: [0; SHA1_BYTE_LENGTH],
            count: Some(Ok(2)),
        };

        let bytes_line = TEST_LINE.as_bytes();
        record.parse_new_hash(bytes_line).unwrap();
        assert_matches!(record.count, None);

        assert_matches!(record.parse_count(bytes_line), Ok(4));
        assert_matches!(record.count, Some(Ok(4)));

        assert_eq!(
            HEXUPPER.encode(&record.hash),
            "000000005AD76BD555C1D6D771DE417A4B87E4B4"
        );
    }

    #[test]
    fn test_number_parse_error() {
        let bytes_line = INVALID_INT.as_bytes();
        let record: PwnedHash = bytes_line.try_into().unwrap();
        let res = record.count.unwrap();
        assert_matches!(res, Err(IntError(_)));
    }
}
