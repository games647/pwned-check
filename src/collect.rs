use core::fmt;
use std::{
    fs::File,
    thread,
};
use std::fmt::Display;
use std::hash::{Hash, Hasher};

use crossbeam_channel::{
    bounded,
    Receiver,
    Sender,
    SendError,
};
use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY};
use serde::Deserialize;
use serde::export::Formatter;

const PASSWORD_BUFFER: usize = 128;

#[derive(Debug, Eq)]
pub struct SavedHash {
    pub url: String,
    pub username: String,
    pub password_hash: String,
}

impl Hash for SavedHash {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.password_hash.hash(state);
    }
}

impl PartialEq for SavedHash {
    fn eq(&self, other: &Self) -> bool {
        self.password_hash == other.password_hash
    }
}

impl Display for SavedHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.username, self.url)
    }
}

pub fn collect_hashes(password_reader: csv::Reader<File>) -> Result<Vec<SavedHash>, ()> {
    let threads = num_cpus::get();
    println!("Started {} hashing threads", threads);

    let (tx, rx): (Sender<SavedPassword>, Receiver<SavedPassword>) = bounded(PASSWORD_BUFFER);
    let (done, quit): (Sender<SavedHash>, Receiver<SavedHash>) = bounded(0);
    for _ in 0..threads {
        let local_rx = rx.clone();
        let local_done = done.clone();
        thread::spawn(move || {
            for in_record in local_rx {
                let in_record: SavedPassword = in_record;
                let hash = hash_pass(&in_record.password);

                let record = SavedHash {
                    url: in_record.url,
                    username: in_record.username,
                    password_hash: hash
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

fn read_passwords(tx: Sender<SavedPassword>,
                  mut file_reader: csv::Reader<File>) -> Result<(), SendError<SavedPassword>> {
    for result in file_reader.deserialize() {
        let record: SavedPassword = result.unwrap();
        tx.send(record)?;
    }

    Ok(())
}

fn hash_pass(pass: &str) -> String {
    let digest = digest(&SHA1_FOR_LEGACY_USE_ONLY, pass.as_bytes());
    digest
        .as_ref()
        .iter()
        .map(|x| format!("{:02x}", x))
        .collect::<String>()
}

#[cfg(test)]
mod test {
    use super::*;

    const HASH_EXPECTED: &str = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";

    #[test]
    fn test_hash() {
        assert_eq!(
            hash_pass("hello"),
            HASH_EXPECTED
        )
    }

    #[test]
    fn test_hash_failed() {
        assert_ne!(
            hash_pass("fail"),
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
