# Pwned-Check

## Description

Small application to scan exported passwords from chromium or FireFox against the offline hash database from
[haveibeenpwned](https://haveibeenpwned.com) in order to verify if any password is exposed.

The exported passwords are read and hashed in parallel. The resulting hashes are then compared to the database. Current
implementation is only targeted for personal use. This means that we expect only single iterations through the database.
For multiple searches (like an online service) an intermediate index or
[bloom filter](https://github.com/bertrand-maujean/ihbpwbf) would improve performance greatly.

This project is also intended for learning Rust (incl. parallelism with channel communication) and its ecosystem.
Feedback appreciated.

## Features

* Offline
* Multi-Threaded

## ToDo

* Thread pool
* Use more generics like Read instead of concrete types
* Chunked benchmark
* Sort hashes (unstable)
* Find hash
* Report count + URL
* Optimize searching in txt file
* Thread scope
* Benchmark - Criterion
    * Multi-Threaded SHA-1 vs Single
    * Multi Threaded file reading (Consumer) vs No Copy
* Properly structure it using error objects (removing `unwrap`)
* Read as ASCII not UTF-8

## Password recommendations

* Use unique passwords for each account
    * A hacked account or website won't impact the accounts from other sites
* Use automatically generated passwords
    * A Password manager is your friend here

## Installation

> git clone REPOSITORY_URL

> cargo build --release

Then you can find the executable in the `target/release` directory

## Usage

1. Download the database from https://haveibeenpwned.com/Passwords (Torrent recommended for reduced load). This tool
   expects the list to be sorted by hash for better efficiency and to have only SHA-1 hashes.
2. Unpack the downloaded file
2. Export your existing passwords somewhere safe. **Note**: A persistent storage isn't a good idea, because the file
   could be restored even if deleted. You could store it in memory (ex: Linux in /dev/shm) and delete it later.
    * FireFox: Open `about:logins` and click the three `horizontal` dots. There you can export logins.
    * Chromium: Open `chrome://settings/passwords` and click the three `vertical` dots on the right side to export it
3. Run the executable of this project with the following usage:

> pwned-check <EXPORTED_CSV> <DOWNLOADED_HASH_TXT> [-v]

## Learned

* Lifetimes help to guarantee the scope of variable where you use non-copy operations
* `FromStr` doesn't support lifetimes.
    * Instances where you need to deserialize from a `&str` and the result uses a substring of
    the original, an owned representation from `to_string` (implying a memory allocation) isn't always necessary.
  * Alternative you could use `impl<'a> TryFrom<&'a str> for YOUR_TRAIT/STRUCT<'a>` for this functionality
  * Or consuming it with the owned `String` where you modify 
* Passing closures without capture (`map(do_something)`) only work if the type matches exactly
    * `fn hash_func(x: &[u8])` can be only called if the type is a slice and not a Vec
    * However, it works with a capture `data.iter().map(|x| do_something(x)).collect()`
    * Alternative: `data.iter().map(Vec::as_slice).map(hash_string).collect()`
* Rust gives you so much flexible to even use the read BUFFER if you guarantee its lifetime
* Rust performs many in-place operations without allocating
* `parse` convert easily types (String -> integer) or even errors to others
* Result objects
    * Can be very easily returned early using `?`
    * Easy matching on the source of error (i.e. Integer parsing error because of X)
        * Without the need to fiddling with Strings
* For loops without `&` are consuming alternative `for &i in &v`
* `do_something(xyz: TYPE)` vs `do_something(xyz: &TYPE)`
    * First one takes the ownership - This could be useful if the function requires ownership (like saving it) or if it
      fully consumes the resource. Copy types like Integers will be automatically copied. It could imply better
      performance. Otherwise, a clone needs to be issued explicitly.
    * Second one temporarily borrows a reference to the variable until the function is finished
* Great tools
    * Clippy (`cargo clippy`) - Like `findbugs` finds potential issues
    * Fmt (`cargo fmt`) - Formatter
    * Check (`cargo check`) - Compile check
    * Documentation testing

### Discovered optimizations

https://llogiq.github.io/2017/06/01/perf-pitfalls.html

* Always release
* Buffered I/O
* Use custom if it fits your data
* Iterate rather than index
* Avoid collect in intermediate variables
* Use slices instead of Vec for no resizable operations or arrays if known at compile-time
* mem::replace when switching values
* Keep attention to passing closures vs invoking them directly
    * Ex: Mapping to a default value

???

* &str instead of String

* Use channels and parallel threads for computation if partitioning is possible
* Performance through `cargo build --release` is huge
* Drop string parsing if possible like csv - `ByteRecords`
* Optimize CPU usage
    * Keep `syscalls` to a minimum
    * Process close to data
    * Cache friendly usage and fewer allocations
* Drop allocations or copies as much as possible
    * Re-use csv records if possible including not yet serialized data
        * Better to use read_record into an existing `StringRecord`/`ByteRecord` and then call deserialize
    * Rust often uses in-place modifications - therefore
        * `format!` allocates a new string
        * `Reader.lines() allocates a new string
        * `String` is owned - while `&str` is borrowed and lifetimes have to keep updated
