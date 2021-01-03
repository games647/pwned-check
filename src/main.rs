use std::fs::File;

use clap::{App, Arg, crate_description, crate_name, crate_version};

const PASSWORD_KEY: &str = "passwords_file";
const HASH_KEY: &str = "hash_file";
const VERBOSE_KEY: &str = "verbose";

fn main() {
    let matches = create_args().get_matches();

    // unwrap is safe here, because the two arguments are required
    let passwords_file = matches.value_of_os(PASSWORD_KEY).unwrap();
    let hash_file = matches.value_of_os(HASH_KEY).unwrap();

    let verbose = matches.is_present(VERBOSE_KEY);
    if verbose {
        println!("Using passwords file: {:?}", passwords_file);
        println!("Using hash file: {:?}", hash_file);
    }

    let hash_file = File::open(hash_file).expect("Hash file not accessible");
    let reader = csv::Reader::from_path(passwords_file).expect("password file not accessible");
    run(reader, hash_file);
}

fn create_args<'help>() -> App<'help> {
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

fn run(password_reader: csv::Reader<File>, hash_file: File) {
    collect::collect_hashes(password_reader);
    find::find_hash(&hash_file);
}

mod collect;
mod find;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse() {
        let args = vec!["pwned-check", "./xyz.txt", "abc.txt"];
        let matches = create_args().try_get_matches_from(args);

        assert!(matches.is_ok(), "CLI parse result {:?}", matches);
    }

    #[test]
    fn test_verbose() {
        let args = vec!["pwned-check", "./xyz.txt", "abc.txt", "-v"];
        let matches = create_args().try_get_matches_from(args);

        assert!(matches.is_ok(), "CLI parse result {:?}", matches);
    }
}
