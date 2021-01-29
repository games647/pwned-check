# Pwned-Check

## Description

Small application to scan exported passwords from your password storage against the offline hash database from
[haveibeenpwned](https://haveibeenpwned.com) in order to verify if any password is exposed. It includes many 
performance features, making the scan very fast **without needing any intermediate conversion** of the original hash
database file. Using that it would make it even faster (See [Index](#Index)).

This project is also intended for learning Rust (incl. parallelism with channel communication) and its ecosystem.
Feedback appreciated.

### Features

* Scans the file sequentially in <5min (HDD + cold cache)
* Offline
* Cross-platform
* Clear read passwords from memory
* Progressbar
* Optimized for bulk searches

#### Optimizations

* Multi-Threaded hashing of stored passwords
* Memory mapping if supported
* Sorted linear search by using lexicographically order of the downloaded hash database
* SIMD comparisons
* Read hash database from ASCII
* Re-use allocations if possible - for example database reading only uses borrowed data
* `fadvise` and `madvise` for UNIX based systems

### Design

#### Load saved passwords

Passwords are exported using the browser. This tool reads the csv then in sequential order and submits the records to a
queue. This queue will hash the passwords in parallel based on the number of cores. Here an allocation is required for
each record, because we use keep all data in memory. Currently, it uses channel communication. However, benchmarks
seems to indicate that it's faster (likely due to chunking) to collect the passwords first sequentially and then
parallelize over all data. Nevertheless, this part should only have a minimal effect, because the hash database is
larger. Therefore, optimizing the comparisons are more important.

The records are then sorted according to their hash to be used later. Meanwhile, the plain-text password will be
dropped.

#### Compares

The hash database file is then read using ASCII characters to skip UTF-8 parsing. Afterwards, the hashes are compared
using SIMD. Using their lexicographically order, we reduce the number of multiple comparisons. Internally this will
use [`eq` and
`gt`](https://github.com/rust-lang/packed_simd/blob/f14f6911b277a0f4522eab03db222ee363c6d6d0/src/api/cmp/partial_ord.rs#L19).
Only if the hash is found the number of pwned hash is evaluated lazily.

## Password recommendations

* Use multi-factor authentication to increase steps required
* Use unique passwords for each account
    * A hacked account or website won't impact the accounts from other sites
* Use automatically generated passwords
    * A Password manager is your friend here

## Installation

Requires Rust nightly (due to SIMD usage).

> git clone REPOSITORY_URL

> cargo build --release

Then you can find the executable in the `target/release` directory

## Usage

1. Download the database from https://haveibeenpwned.com/Passwords (Torrent recommended for reduced load). This tool
   expects the list to be sorted by hash for better efficiency and to have only SHA-1 hashes.
2. Unpack the downloaded file
2. Export your existing passwords somewhere safe.
    * **Warning**: A persistent storage isn't a good idea, because the file could be restored even if deleted. You
      could store it in memory (ex: Linux in /tmp depending on the permissions) and delete it later (`shred`). Even
      then other applications or users could access it. For later make sure, only you have read permission.
    * Firefox: Open `about:logins` and click the three `horizontal` dots. There you can export logins.
    * Chromium: Open `chrome://settings/passwords` and click the three `vertical` dots on the right side to export it
3. Run the executable of this project with the following usage:

> pwned-check <EXPORTED_CSV> <DOWNLOADED_HASH_TXT> [-v]

```
./pwned-check password.csv pwned-passwords-sha1-ordered-by-hash-v7.txt -v
987.70 MB / 25.18 GB [=>----------------------------------] 3.83 % 493.84 MB/s 50s
Your password for the following account USERNAME@WEBSITE has been pwned 25x times
...
3.36 GB / 25.18 GB [======>-----------------------------] 13.32 % 490.78 MB/s 46s
...
104.71 MB/s Finished
```

## Discovered optimizations

* Build with release tag `cargo build --release` has massive impact
* Collecting data and then parallelize could improve performance
    * Ex: Collect all data in-memory, chunk data and then run in parallel (like
      with [rayon](https://github.com/rayon-rs/rayon))
    * Benchmarks here showed that the overhead of communication (incl. sending only a few data) can be big
      (i.e. pipelining)
* Sometimes sequential processing could be faster due data inside the cache
* Drop allocations or copies and re-use variables if it's critical for you
    * `format!` allocates a new string
* SIMD can easily improve performance if you're dealing with
    * However, they have to fit in the supported registers exactly (i.e. u8 * 32), otherwise they need to be resized
    * Different architecture - independent vertical operations on each u8
    * Performance could vary depending on the compiler settings
      (`target-cpu=native` and LTO had very negative influence)

### CSV Crate Suggestions

* Drop UTF-8 decoding if not necessary (`ByteRecord`)
* Drop per line/record allocations - Try to re-use them
    * Applies to BuffLines as well for records in csv
* Use borrowed data instead of owned data, because later often requires copy
    * Ex: For example: `&'a str` for records

### Pitfalls

* Standard I/O is unbuffered - use buffered if applicable
* Use `target-cpu=native` to leverage specific optimizations - however experiences may differ
* Reduce UTF-8 and line allocations - see above
* Use a custom hasher if it fits your data (like FX) or Indexmap
* `println!` performs a lock on each all call
* Iterate rather than an index loop
* Avoid collect into intermediate variables
* Static values could use arrays instead of `Vec<T>`
* mem::replace when switching values
* Keep attention to passing closures vs invoking them directly
    * Ex: Mapping to a default value

Source https://llogiq.github.io/2017/06/01/perf-pitfalls.html

### Read/Memory Map/DIO

* Memory mapping is expensive to open, but for big files worth it
* No copies from kernel space to user space
* Reduce the number of page files
* User vs Kernel caching
* Hides I/O behind page faults
* Other process could write to the file or page -> causing unsafe behavior

Source: https://www.scylladb.com/2017/10/05/io-access-methods-scylla/

## Further optimizations

All this requires benchmarking first.

### Index

This tool is specifically designed for individuals. So the main use case is to do only a single run. There are tools
like [csv-index](https://docs.rs/csv-index/) that could create an intermediate index over the data. This could be useful
for concurrent access to the file.

### Binary searching

Currently, we scan the entries and compare them using their lexicographically order. We could also skip a couple of
hashes from the database, because it's likely that there are many more hashes than user stored ones. This requires us to
jump back if we skipped too far. Nevertheless, this requires benchmarking also considering that we will destroy the CPU
performance features (Branch predictor, Pipelining).

### Parallel compares

Similar to the previous points, it's possible to scan the hash database file using concurrent file accesses. Using the
index (to know the number of bytes from line numbers) and binary searching, we could skip multiple operating system
pages. SSD drives could benefit the most.

### Bloom filter

There also other projects that developed an intermediate filter to improve the search
([bloom-filter]([bloom filter](https://github.com/bertrand-maujean/ihbpwbf))). However, this requires a full run through
the data. As said [before](#Index), this doesn't seem practical here.

## Learned

* Lifetimes help to guarantee the scope of variable where you use non-copy operations
    * In-place operations or I/O buffer use without `memcpy` or allocation
* `FromStr` doesn't support lifetimes.
    * Instances where you need to deserialize from a `&str` and the result uses a substring of the original, an owned
      representation from `to_string` (implying a memory allocation) isn't always necessary.
    * Alternative you could use `impl<'a> TryFrom<&'a str> for YOUR_TRAIT/STRUCT<'a>` for this functionality
    * Or consuming it with the owned `String`
* Passing closures without capture (`map(self::do_something)`) only work if the type matches exactly
    * `fn hash_func(x: &[u8])` can be only called if the type is a slice and not a Vec
    * Alternative: `data.iter().map(Vec::as_slice).map(hash_string).collect()`
* `parse` convert easily types (String -> integer) or even errors to others
* Result objects can be very easily returned early using `?` and supports matchable reason
* For loops without `&` are consuming alternative `for &i in &v`
* `do_something(xyz: TYPE)` vs `do_something(xyz: &TYPE)`
    * First one takes the ownership - This could be useful if the function requires ownership (like saving it) or if it
      fully consumes the resource. Copy types like Integers will be automatically copied. It could imply better
      performance. Otherwise, a clone needs to be issued explicitly.
    * Second one temporarily borrows a reference to the variable until the function is finished
* Great tools
    * Clippy (`cargo clippy`) - Like `findbugs` finds potential issues and runs `cargo check` for compile time errors
    * Fmt (`cargo fmt`) - Formatter
    * Documentation testing
* AsRef for cheap conversions
* Building arrays at compile time is only possible with `const fn`, but it forbids a lot of things like for
    * Code generation with `build.rs` is also possible, but complicated
    * Alternative: Crates like `init_with`
