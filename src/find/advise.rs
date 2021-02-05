use std::{error::Error, fmt, fs::File, io};

/// Memory mapped advise type
#[repr(i32)]
#[allow(dead_code)]
pub enum MemoryAdvice {
    Normal = libc::POSIX_MADV_NORMAL,
    Sequential = libc::POSIX_MADV_SEQUENTIAL,
    Random = libc::POSIX_MADV_RANDOM,
    WillNeed = libc::POSIX_MADV_WILLNEED,
    DontNeed = libc::POSIX_MADV_DONTNEED,
    // Linux specific entries are missing
}

// Windows:
// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-prefetchvirtualmemory

/// Advise the OS about the usage of this memory page. Linux specific implementation allows
/// zero length and page aligned access according to the man page.
///
/// # Panics
///
/// If the given pointer is null
///
/// # Examples
///
/// ```
/// let mmap = MmapOptions::new().len(8).map_anon().unwrap();
/// // Safety: cast to mutable pointer from immutable source
///  let ptr = mmap.as_ptr() as *mut u8;
/// madvise(ptr, 0, 8, MemoryAdvice::Sequential);
/// ```
pub fn madvise<T>(ptr: *mut T, len: usize, advice: MemoryAdvice) -> Result<(), io::Error> {
    assert!(!ptr.is_null());

    // madvise consumes a pointer - normally they shouldn't change anything of the data behind the
    // pointer - however we don't know that for sure
    let ret = unsafe { libc::madvise(ptr as *mut libc::c_void, len, advice as i32) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// File advise type
#[repr(i32)]
#[allow(dead_code)]
pub enum FileAdvice {
    Normal = libc::POSIX_FADV_NORMAL,
    Sequential = libc::POSIX_FADV_SEQUENTIAL,
    Random = libc::POSIX_FADV_RANDOM,
    NoReuse = libc::POSIX_FADV_NOREUSE,
    WillNeed = libc::POSIX_FADV_WILLNEED,
    DontNeed = libc::POSIX_FADV_DONTNEED,
}

// Windows has something similar with:
// https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#caching-behavior

/// Advise the OS about the intended file access
///
/// The optional length represents the total length, if empty 0 will be specified. This means to
/// the end of the file.
///
/// # Panics
///
/// If the syscall returns unexpected results
///
/// # Examples
///
/// ```
/// let file = File::open(file!());
/// fadvise(file, 0, None, Advice::Sequential);
/// ```
pub fn fadvise(file: &File, offset: i64, length: Option<i64>, advice: FileAdvice) {
    use std::os::unix::io::AsRawFd;

    let fd = file.as_raw_fd();
    let res = unsafe { libc::posix_fadvise(fd, offset, length.unwrap_or(0), advice as i32) };

    // Safety: programming mistakes should panic instead of return an error
    match res {
        0 => Ok(()),
        libc::EBADF => Err(FAdviseError::EBADF),
        libc::EINVAL => Err(FAdviseError::EINVAL),
        libc::ESPIPE => Err(FAdviseError::ESPIPE),
        err => Err(FAdviseError::Unknown(err)),
    }
    .unwrap()
}

#[derive(Debug)]
enum FAdviseError {
    /// No valid file descriptor
    EBADF,
    /// Invalid advise value
    EINVAL,
    /// File descriptor refers to a pipe
    ESPIPE,
    /// Unexpected integer return value
    Unknown(i32),
}

impl fmt::Display for FAdviseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for FAdviseError {}

#[cfg(test)]
mod test {
    use std::{os::unix::io::FromRawFd, panic, ptr};

    use assert_matches::assert_matches;
    use memmap::MmapOptions;

    use super::*;

    #[test]
    #[should_panic]
    fn madvise_null() {
        let ptr: *mut u8 = ptr::null_mut();
        let _ = madvise(ptr, 1, MemoryAdvice::Sequential);
    }

    #[test]
    fn madvise_success() -> Result<(), io::Error> {
        let mmap = MmapOptions::new().len(8).map_anon().unwrap();
        let ptr = mmap.as_ptr() as *mut u8;

        madvise(ptr, 8, MemoryAdvice::DontNeed)
    }

    #[test]
    fn madvise_not_aligned() {
        let ptr = "test".as_ptr();
        let _res = madvise(ptr as *mut u8, 1, MemoryAdvice::Sequential);

        let expected: Result<(), io::Error> = Err(io::Error::from_raw_os_error(libc::EINVAL));
        assert_matches!(expected, _res);
    }

    #[test]
    fn fadvise_success() {
        let file = file!();
        let file = File::open(file).unwrap();
        fadvise(&file, 0, None, FileAdvice::WillNeed);
    }

    #[test]
    fn fadvise_pipe_error() {
        let mut fds: [libc::c_int; 2] = [0; 2];
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };

        if ret != 0 {
            let expected: Result<(), io::Error> = Ok(());
            let _err: Result<(), io::Error> = Err(io::Error::last_os_error());
            assert_matches!(expected, _err);
        }

        let file = unsafe { File::from_raw_fd(fds[0]) };

        // test for panic only inside that closure to not interfere with the unsafe call above
        let result = panic::catch_unwind(|| fadvise(&file, 0, None, FileAdvice::WillNeed));
        assert!(result.is_err());
    }
}
