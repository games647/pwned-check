use std::{fs::File, io::Read};

use clap::{crate_description, crate_name, crate_version, App, Arg};
use log::{debug, error, info};
use ring::digest::SHA1_OUTPUT_LEN;

const PASSWORD_KEY: &str = "passwords_file";
const HASH_KEY: &str = "hash_file";
const VERBOSE_KEY: &str = "verbose";

const SHA1_BYTE_LENGTH: usize = SHA1_OUTPUT_LEN;

type Sha1Hash = [u8; SHA1_BYTE_LENGTH];

fn main() {
    let matches = create_cli_options().get_matches();

    // unwrap is safe here, because the two arguments are required
    let passwords_file = matches.value_of_os(PASSWORD_KEY).unwrap();
    let hash_file = matches.value_of_os(HASH_KEY).unwrap();

    let verbose = matches.is_present(VERBOSE_KEY);
    logger::set_logger(verbose);

    debug!("Using passwords file: {:?}", passwords_file);
    debug!("Using hash file: {:?}", hash_file);

    let hash_file = File::open(hash_file);
    let reader = csv::Reader::from_path(passwords_file);
    match hash_file {
        Err(err) => error!("Cannot access password file {}", err),
        Ok(file) => match reader {
            Err(err) => error!("Cannot access hash file {}", err),
            Ok(reader) => run(reader, file),
        },
    }
}

fn create_cli_options<'help>() -> App<'help> {
    App::new(crate_name!())
        .about(crate_description!())
        .version(crate_version!())
        .arg(
            Arg::new(PASSWORD_KEY)
                .about("Sets passwords csv input list")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new(HASH_KEY)
                .about("SHA-1 hash list sorted by hash")
                .required(true)
                .index(2),
        )
        .arg(
            Arg::new(VERBOSE_KEY)
                .short('v')
                .long("verbose")
                .about("Verbose output"),
        )
}

fn run(password_reader: csv::Reader<impl Read>, hash_file: File) {
    match collect::collect_hashes(password_reader) {
        Ok(mut hashes) => {
            info!("Finished hashing");

            // unstable is slightly faster than the normal search - we don't care about mixed equal
            // entries so lets use this
            hashes.sort_unstable();
            info!("Sorted");

            match find::find_hash(&hash_file, &hashes) {
                Ok(()) => info!("Finished"),
                Err(err) => error!("Aborted: {}", err),
            };
        }
        Err(err) => {
            error!("Failed parse saved passwords: {:?}", err);
        }
    };
}

mod collect;
mod find;
mod logger;

#[cfg(test)]
mod test {
    use super::*;
    use assert_matches::assert_matches;

    #[test]
    fn test_parse() {
        let args = ["pwned-check", "./xyz.txt", "abc.txt"];
        let matches = create_cli_options().try_get_matches_from(&args);

        assert!(matches.is_ok(), "CLI parse result {:?}", matches);
    }

    #[test]
    fn test_verbose() {
        let args = ["pwned-check", "./xyz.txt", "abc.txt", "-v"];
        let matches = create_cli_options().try_get_matches_from(&args);

        assert!(matches.is_ok(), "CLI parse result {:?}", matches);
    }

    #[test]
    fn test_failed_parse() {
        let args = ["pwned-check", "./xyz.txt", "abc.txt", "--non-existing-flag"];
        let matches = create_cli_options().try_get_matches_from(&args);

        assert!(!matches.is_ok(), "CLI parse result {:?}", matches);
    }

    #[test]
    fn test_missing_file() {
        let args = ["pwned-check", "file.txt"];
        let matches = create_cli_options().try_get_matches_from(&args);
        assert_matches!(matches, Err(_));

        let matches = create_cli_options().try_get_matches_from(&args[..1]);
        assert_matches!(matches, Err(_));
    }
}
