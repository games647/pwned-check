use std::fs::File;
use std::io;

/// Memory mapped advise type
#[cfg(unix)]
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

/// Advise the OS about the usage of this memory page
///
/// # Panics
///
/// If the given pointer is null
///
/// # Examples
///
/// ```
/// madvise(file, 0, 0, MEMORY_ADVICE::Sequential);
/// ```
#[cfg(unix)]
pub fn madvise(ptr: *mut (), len: usize, advice: MemoryAdvice) -> Result<(), io::Error> {
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
#[cfg(unix)]
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
/// fadvise(file, 0, None, Advice::Sequential);
/// ```
#[cfg(unix)]
pub fn fadvise(file: &File, offset: i64, length: Option<i64>, advice: FileAdvice) {
    use std::os::unix::io::AsRawFd;

    let fd = file.as_raw_fd();
    let res = unsafe { libc::posix_fadvise(fd, offset, length.unwrap_or(0), advice as i32) };
    match res {
        0 => Ok(()),
        libc::EBADF => Err(FAdviseError::EBADF),
        libc::EINVAL => Err(FAdviseError::EINVAL),
        libc::ESPIPE => Err(FAdviseError::ESPIPE),
        err => Err(FAdviseError::Unknown(err))
    }.unwrap()
}

#[cfg(unix)]
#[derive(Debug)]
enum FAdviseError {
    EBADF,
    EINVAL,
    ESPIPE,
    Unknown(i32),
}
