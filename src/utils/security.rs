//! Windows security descriptors stored with the files they guard.
//!
//! The server never interprets a descriptor: it keeps the self-relative bytes
//! a client set and hands them back, and the client's kernel does the access
//! check. A descriptor lives on the file itself - an extended attribute on
//! Unix, an alternate data stream on Windows - so it moves with a rename and
//! goes with a delete, and there is no side table to fall out of step.
//!
//! An entry with no descriptor inherits from the directory it is in, which is
//! every entry until someone sets one. So that a listing of such a tree costs
//! one lookup rather than one per child, a directory is marked when any child
//! is given a descriptor, and only a marked directory has its children read.

use bytes::Bytes;
use std::path::Path;

/// Largest descriptor accepted: far above any real ACL, and small enough that
/// a listing of thousands of distinct descriptors stays bounded.
pub const MAX_DESCRIPTOR_BYTES: usize = 64 * 1024;

/// `SECURITY_DESCRIPTOR_RELATIVE`: revision, padding, control, then four
/// offsets.
const HEADER_BYTES: usize = 20;

/// `SE_SELF_RELATIVE` in the control word.
const SELF_RELATIVE: u16 = 0x8000;

/// Whether `bytes` has the shape of a self-relative descriptor.
///
/// Revision 1, the self-relative bit, and every offset inside the buffer. The
/// client validates fully before it uses one; this only keeps out what could
/// not be one at all.
pub fn valid(bytes: &[u8]) -> bool {
    if bytes.len() < HEADER_BYTES || bytes.len() > MAX_DESCRIPTOR_BYTES || bytes[0] != 1 {
        return false;
    }

    if u16::from_le_bytes([bytes[2], bytes[3]]) & SELF_RELATIVE == 0 {
        return false;
    }

    bytes[4..HEADER_BYTES]
        .as_chunks::<4>()
        .0
        .iter()
        .all(|offset| {
            let offset = u32::from_le_bytes(*offset);
            offset == 0
                || usize::try_from(offset)
                    .is_ok_and(|offset| offset >= HEADER_BYTES && offset < bytes.len())
        })
}

/// The descriptor stored on `path`, or `None` if it inherits.
pub fn read(path: &Path) -> Option<Bytes> {
    let bytes = platform::get(path, platform::DESCRIPTOR)?;

    valid(&bytes).then(|| Bytes::from(bytes))
}

/// The descriptor of the nearest directory above `path`, up to and including
/// `base`, that has one stored, and how many levels up it is.
pub fn nearest_above(path: &Path, base: &Path) -> Option<(Bytes, u32)> {
    path.ancestors()
        .skip(1)
        .take_while(|ancestor| ancestor.starts_with(base))
        .zip(1..)
        .find_map(|(ancestor, depth)| Some((read(ancestor)?, depth)))
}

/// Whether any child of `directory` has a descriptor of its own.
pub fn marked(directory: &Path) -> bool {
    platform::get(directory, platform::MARK).is_some()
}

/// Stores `descriptor` on `path`, or removes it so `path` inherits again.
///
/// Marks `directory`, the one `path` is listed in, first, so that a listing
/// never misses a descriptor that is already in place. The served root is
/// listed in nothing the server answers for, so it passes `None`.
///
/// # Errors
///
/// The underlying I/O error; a filesystem without extended attributes or
/// streams answers `Unsupported`.
pub fn write(
    path: &Path,
    descriptor: Option<&[u8]>,
    directory: Option<&Path>,
) -> std::io::Result<()> {
    match descriptor {
        Some(descriptor) => {
            if let Some(directory) = directory {
                platform::set(directory, platform::MARK, &[])?;
            }

            platform::set(path, platform::DESCRIPTOR, descriptor)
        }
        None => platform::remove(path, platform::DESCRIPTOR),
    }
}

#[cfg(unix)]
mod platform {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Path;

    pub const DESCRIPTOR: &str = "user.blorgfs.sd";
    pub const MARK: &str = "user.blorgfs.sdmark";

    fn c_path(path: &Path) -> std::io::Result<CString> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| std::io::ErrorKind::InvalidInput.into())
    }

    fn c_name(name: &str) -> CString {
        // The names are the constants above, which hold no NUL.
        CString::new(name).unwrap_or_default()
    }

    /// Asks for the length first, so that the common answer - nothing
    /// stored - costs one syscall and no allocation.
    pub fn get(path: &Path, name: &str) -> Option<Vec<u8>> {
        let path = c_path(path).ok()?;
        let name = c_name(name);

        // SAFETY: both strings are NUL-terminated; a zero length with a null
        // buffer only asks for the size.
        let length =
            unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };

        let length = usize::try_from(length).ok()?;
        if length > super::MAX_DESCRIPTOR_BYTES {
            return None;
        }

        let mut buffer = vec![0_u8; length];

        // SAFETY: both strings are NUL-terminated and the buffer is as long
        // as the length passed. A value that grew in between fails with
        // `ERANGE`, and the watcher's event for that write rescans.
        let length = unsafe {
            libc::getxattr(
                path.as_ptr(),
                name.as_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };

        let length = usize::try_from(length).ok()?;
        buffer.truncate(length);

        Some(buffer)
    }

    pub fn set(path: &Path, name: &str, value: &[u8]) -> std::io::Result<()> {
        let path = c_path(path)?;
        let name = c_name(name);

        // SAFETY: both strings are NUL-terminated and the value is as long as
        // the length passed.
        let result = unsafe {
            libc::setxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        };

        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    pub fn remove(path: &Path, name: &str) -> std::io::Result<()> {
        let path = c_path(path)?;
        let name = c_name(name);

        // SAFETY: both strings are NUL-terminated.
        let result = unsafe { libc::removexattr(path.as_ptr(), name.as_ptr()) };

        if result == 0 {
            return Ok(());
        }

        let error = std::io::Error::last_os_error();

        // Removing what is not there leaves the entry inheriting, which is
        // what was asked.
        if error.raw_os_error() == Some(libc::ENODATA) {
            Ok(())
        } else {
            Err(error)
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::io::{Read as _, Write as _};
    use std::path::{Path, PathBuf};

    pub const DESCRIPTOR: &str = "blorgfs.sd";
    pub const MARK: &str = "blorgfs.sdmark";

    fn stream(path: &Path, name: &str) -> PathBuf {
        let mut spelled = path.as_os_str().to_owned();
        spelled.push(":");
        spelled.push(name);
        PathBuf::from(spelled)
    }

    pub fn get(path: &Path, name: &str) -> Option<Vec<u8>> {
        let file = std::fs::File::open(stream(path, name)).ok()?;
        let mut buffer = Vec::new();

        // One past the limit, so that a longer stream is refused rather than
        // cut short.
        file.take(u64::try_from(super::MAX_DESCRIPTOR_BYTES + 1).unwrap_or(u64::MAX))
            .read_to_end(&mut buffer)
            .ok()?;

        (buffer.len() <= super::MAX_DESCRIPTOR_BYTES).then_some(buffer)
    }

    pub fn set(path: &Path, name: &str, value: &[u8]) -> std::io::Result<()> {
        std::fs::File::create(stream(path, name))?.write_all(value)
    }

    pub fn remove(path: &Path, name: &str) -> std::io::Result<()> {
        match std::fs::remove_file(stream(path, name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use std::path::Path;

    pub const DESCRIPTOR: &str = "";
    pub const MARK: &str = "";

    pub const fn get(_: &Path, _: &str) -> Option<Vec<u8>> {
        None
    }

    pub fn set(_: &Path, _: &str, _: &[u8]) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    pub const fn remove(_: &Path, _: &str) -> std::io::Result<()> {
        Ok(())
    }
}
