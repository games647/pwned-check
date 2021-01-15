use std::{
    fmt::Display,
    hash::{Hash, Hasher},
    thread,
};
use std::io::Read;

use crossbeam_channel::{bounded, Receiver, Sender, SendError};
use ring::digest::{digest, Digest, SHA1_FOR_LEGACY_USE_ONLY};
use serde::Deserialize;
use serde::export::Formatter;

const PASSWORD_BUFFER: usize = 128;

#[derive(Debug)]
pub struct SavedHash {
    pub url: String,
    pub username: String,
    pub password_hash: Digest,
}

impl Hash for SavedHash {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.password_hash.as_ref().hash(state);
    }
}

impl PartialEq for SavedHash {
    fn eq(&self, other: &Self) -> bool {
        self.password_hash.as_ref() == other.password_hash.as_ref()
    }
}

// marker interface only
impl Eq for SavedHash {}

impl Display for SavedHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.username, self.url)
    }
}

pub fn collect_hashes(password_reader: csv::Reader<impl Read>) -> Result<Vec<SavedHash>, ()> {
    let threads = num_cpus::get();
    println!("Started {} hashing threads", threads);

    let (tx, rx) = bounded(PASSWORD_BUFFER);
    let (done, quit) = bounded(0);
    for _ in 0..threads {
        let local_rx: Receiver<SavedPassword> = rx.clone();
        let local_done = done.clone();
        thread::spawn(move || {
            for in_record in local_rx {
                let password_hash = hash_pass(&in_record.password);
                let record = SavedHash {
                    url: in_record.url,
                    username: in_record.username,
                    password_hash,
                };

                local_done.send(record).unwrap();
            }

            // drop it explicitly so we could notice the done signal
            drop(local_done);
        });
    }

    // drop the original done, so that all done variants including the clones are dropped
    drop(done);

    // read passwords on the current thread and wait until the receivers are finished
    read_passwords(tx, password_reader).unwrap();

    // detect when all done channels are dropped this loop breaks
    Ok(quit.iter().collect())
}

#[derive(Debug, Deserialize)]
struct SavedPassword {
    url: String,
    username: String,
    password: String,
}

fn read_passwords(
    tx: Sender<SavedPassword>,
    mut file_reader: csv::Reader<impl Read>,
) -> Result<(), SendError<SavedPassword>> {
    for result in file_reader.deserialize() {
        let record: SavedPassword = result.unwrap();
        tx.send(record)?;
    }

    Ok(())
}

fn hash_pass(pass: &str) -> Digest {
    digest(&SHA1_FOR_LEGACY_USE_ONLY, pass.as_bytes())
}

#[cfg(test)]
mod test {
    use data_encoding::HEXLOWER;

    use super::*;

    const HASH_EXPECTED: &str = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";

    #[test]
    fn test_hash() {
        assert_eq!(HEXLOWER.encode(hash_pass("hello").as_ref()), HASH_EXPECTED)
    }

    #[test]
    fn test_hash_failed() {
        assert_ne!(
            HEXLOWER.encode(hash_pass("fail").as_ref()),
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        )
    }

    #[test]
    fn parse_chromium_csv() -> Result<(), csv::Error> {
        let data = "name,url,username,password
hello,https://www.rust-lang.org/,user,pass";
        validate_parse(data)
    }

    #[test]
    fn parse_firefox_csv() -> Result<(), csv::Error> {
        // use r#"XYZ"# to escape " inside the string - Warning " are also necessary
        let data = r#""url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged""
""https://www.rust-lang.org/","user","pass",,"https://www.rust-lang.org/","{00000000-0000-0000-0000-0000000000000000}","-1","-2","-3""#;
        validate_parse(data)
    }

    fn validate_parse(data: &str) -> Result<(), csv::Error> {
        let mut reader = csv::Reader::from_reader(data.as_bytes());
        for result in reader.deserialize() {
            let record: SavedPassword = result?;
            assert_eq!(record.url, "https://www.rust-lang.org/");
            assert_eq!(record.username, "user");
            assert_eq!(record.password, "pass");
        }

        Ok(())
    }
}
