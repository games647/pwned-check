use std::fs::File;
use std::thread;

use crossbeam_channel::bounded;
use crossbeam_channel::Receiver;
use crossbeam_channel::select;
use crossbeam_channel::Sender;
use crossbeam_channel::SendError;
use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY};
use serde::Deserialize;

const PASSWORD_BUFFER: usize = 128;

#[derive(Debug, Deserialize)]
struct PasswordRecord {
    url: String,
    username: String,
    password: String,
}

pub fn collect_hashes(password_reader: csv::Reader<File>) {
    let (done, quit): (Sender<_>, Receiver<()>) = bounded(0);

    let threads = num_cpus::get();
    println!("Started {} hashing threads", threads);

    // end is exclusive so start with 0
    let (tx, rx): (Sender<String>, Receiver<String>) = bounded(PASSWORD_BUFFER);
    for _ in 0..threads {
        let local_rx = rx.clone();
        let local_done = done.clone();
        thread::spawn(move || {
            for pass in local_rx {
                let hash = hash_pass(&pass);
                println!("HASH: {}", hash);
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
    loop {
        select! {
            recv(quit) -> _ => break,
        }
    }

    println!("Finished hashing");
}

fn read_passwords(tx: Sender<String>,
                  mut file_reader: csv::Reader<File>) -> Result<(), SendError<String>> {
    for result in file_reader.deserialize() {
        let record: PasswordRecord = result.unwrap();
        tx.send(record.url)?;
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
            let record: PasswordRecord = result?;
            assert_eq!(record.url, "https://www.rust-lang.org/");
            assert_eq!(record.username, "user");
            assert_eq!(record.password, "pass");
        }

        Ok(())
    }
}
