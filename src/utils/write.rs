//! Changes a client makes to the served tree.
//!
//! Everything here blocks, and runs on the blocking pool;
//! [`crate::utils::cache::Store`] decides what each change invalidates and
//! publishes it to the feed once it is made.
//!
//! A write to a file's bytes names the version it was made against, as the
//! entity tag a read of that version carried, and is refused if the file has
//! moved on since: two clients writing one file fail rather than silently
//! overwrite each other. That only holds if every change to the bytes changes
//! the tag, so a change that left the modification time where it was - a
//! coarse clock, two writes in one tick - moves it on by hand.

use crate::error::AppError;
use std::fs::{File, Metadata};
use std::path::Path;
use std::time::{Duration, SystemTime};

/// The strong entity tag of a file of `len` bytes last modified at `modified`.
///
/// Spelled the way the streaming file service spells its own, so that a file
/// carries one tag whether it is served from memory or streamed.
pub fn entity_tag(modified: SystemTime, len: u64) -> Option<String> {
    let since = modified.duration_since(SystemTime::UNIX_EPOCH).ok()?;

    Some(format!(
        "\"{:x}.{:08x}-{len:x}\"",
        since.as_secs(),
        since.subsec_nanos()
    ))
}

/// The tag `metadata` describes.
pub fn tag_of(metadata: &Metadata) -> Option<String> {
    entity_tag(metadata.modified().ok()?, metadata.len())
}

/// Refuses unless `file` is still the version `if_match` names. `*` names
/// any version, as in HTTP.
fn check(file: &File, if_match: &str) -> Result<SystemTime, AppError> {
    let metadata = file.metadata()?;
    let modified = metadata.modified()?;

    if if_match != "*" && tag_of(&metadata).as_deref() != Some(if_match) {
        return Err(AppError::PreconditionFailed);
    }

    Ok(modified)
}

/// Makes sure `file`'s modification time is past `before`.
///
/// A microsecond is enough on any filesystem that keeps finer times than a
/// second, and is not a visible lie; one that keeps whole seconds needs the
/// second.
fn advance(file: &File, before: SystemTime) -> std::io::Result<()> {
    if file.metadata()?.modified()? > before {
        return Ok(());
    }

    for step in [Duration::from_micros(1), Duration::from_secs(1)] {
        file.set_modified(before + step)?;

        if file.metadata()?.modified()? > before {
            break;
        }
    }

    Ok(())
}

/// Writes `data` at `offset` in the file at `path`, extending it if the
/// write runs past its end, provided it is still the version `if_match`
/// names.
///
/// # Errors
///
/// [`AppError::PreconditionFailed`] if it is not, and the usual I/O mappings.
pub fn write_at(path: &Path, offset: u64, data: &[u8], if_match: &str) -> Result<(), AppError> {
    let file = File::options().write(true).open(path)?;
    let before = check(&file, if_match)?;

    platform::write_all_at(&file, data, offset)?;
    advance(&file, before)?;

    Ok(())
}

/// Truncates or extends the file at `path` to `size` bytes, provided it is
/// still the version `if_match` names.
///
/// # Errors
///
/// [`AppError::PreconditionFailed`] if it is not, and the usual I/O mappings.
pub fn set_len(path: &Path, size: u64, if_match: &str) -> Result<(), AppError> {
    let file = File::options().write(true).open(path)?;
    let before = check(&file, if_match)?;

    file.set_len(size)?;
    advance(&file, before)?;

    Ok(())
}

/// Sets whichever of the times are given on the entry at `path`, a file or a
/// directory. Creation times are kept only where the filesystem keeps them.
///
/// # Errors
///
/// The usual I/O mappings.
pub fn set_times(
    path: &Path,
    created: Option<SystemTime>,
    modified: Option<SystemTime>,
    accessed: Option<SystemTime>,
) -> Result<(), AppError> {
    let mut times = std::fs::FileTimes::new();

    if let Some(modified) = modified {
        times = times.set_modified(modified);
    }

    if let Some(accessed) = accessed {
        times = times.set_accessed(accessed);
    }

    times = platform::with_created(times, created);

    platform::open_attributes(path)?.set_times(times)?;

    Ok(())
}

/// Creates a file or directory named `name` in the directory `parent`.
///
/// Fails if anything already has that name, and stores `descriptor` on the
/// new entry if one is given. A descriptor that cannot be stored takes the new entry
/// with it, so nothing is left behind under a looser one than was asked for.
///
/// # Errors
///
/// [`AppError::Conflict`] if the name is taken, and the usual I/O mappings.
pub fn create(
    parent: &Path,
    name: &str,
    directory: bool,
    descriptor: Option<&[u8]>,
) -> Result<(), AppError> {
    let path = parent.join(name);

    if directory {
        std::fs::create_dir(&path)?;
    } else {
        File::options().write(true).create_new(true).open(&path)?;
    }

    let Some(descriptor) = descriptor else {
        return Ok(());
    };

    if let Err(error) = crate::utils::security::write(&path, Some(descriptor), Some(parent)) {
        let _ = if directory {
            std::fs::remove_dir(&path)
        } else {
            std::fs::remove_file(&path)
        };

        return Err(error.into());
    }

    Ok(())
}

/// Removes the file or empty directory at `path`.
///
/// # Errors
///
/// [`AppError::Conflict`] for a directory that is not empty, and the usual I/O
/// mappings.
pub fn remove(path: &Path) -> Result<(), AppError> {
    if std::fs::symlink_metadata(path)?.is_dir() {
        std::fs::remove_dir(path)?;
    } else {
        std::fs::remove_file(path)?;
    }

    Ok(())
}

/// Moves the entry at `from` to `to`, replacing what is there only if
/// `replace` is set. Replacing a directory, or with one, is refused, as
/// Windows refuses it.
///
/// # Errors
///
/// [`AppError::Conflict`] if `to` is taken and may not be replaced, and the
/// usual I/O mappings.
pub fn rename(from: &Path, to: &Path, replace: bool) -> Result<(), AppError> {
    if replace {
        if let Ok(existing) = std::fs::symlink_metadata(to)
            && (existing.is_dir() || std::fs::symlink_metadata(from)?.is_dir())
        {
            return Err(AppError::Conflict);
        }

        std::fs::rename(from, to)?;
        return Ok(());
    }

    platform::rename_no_replace(from, to)?;

    Ok(())
}

#[cfg(unix)]
mod platform {
    use std::fs::File;
    use std::os::unix::fs::FileExt as _;
    use std::path::Path;

    pub fn write_all_at(file: &File, data: &[u8], offset: u64) -> std::io::Result<()> {
        file.write_all_at(data, offset)
    }

    pub const fn with_created(
        times: std::fs::FileTimes,
        _: Option<std::time::SystemTime>,
    ) -> std::fs::FileTimes {
        times
    }

    /// `futimens` needs only ownership, not write access, so a read-only
    /// handle serves files and directories alike.
    pub fn open_attributes(path: &Path) -> std::io::Result<File> {
        File::open(path)
    }

    /// `renameat2` refuses atomically when `to` exists.
    #[cfg(target_os = "linux")]
    pub fn rename_no_replace(from: &Path, to: &Path) -> std::io::Result<()> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;

        let from = CString::new(from.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let to = CString::new(to.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;

        // SAFETY: both strings are NUL-terminated and outlive the call.
        let result = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };

        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// Without `renameat2` a hard link claims `to` atomically for a file; a
    /// directory can only be checked first.
    #[cfg(not(target_os = "linux"))]
    pub fn rename_no_replace(from: &Path, to: &Path) -> std::io::Result<()> {
        if std::fs::symlink_metadata(from)?.is_dir() {
            if std::fs::symlink_metadata(to).is_ok() {
                return Err(std::io::ErrorKind::AlreadyExists.into());
            }

            return std::fs::rename(from, to);
        }

        std::fs::hard_link(from, to)?;
        std::fs::remove_file(from)
    }
}

#[cfg(windows)]
mod platform {
    use std::fs::File;
    use std::os::windows::fs::{FileExt as _, FileTimesExt as _, OpenOptionsExt as _};
    use std::path::Path;

    /// `FILE_WRITE_ATTRIBUTES`: enough to set times, and grantable on a
    /// directory, which a plain write handle is not.
    const WRITE_ATTRIBUTES: u32 = 0x0100;

    /// `FILE_FLAG_BACKUP_SEMANTICS`, without which a directory cannot be
    /// opened at all.
    const BACKUP_SEMANTICS: u32 = 0x0200_0000;

    pub fn write_all_at(file: &File, mut data: &[u8], mut offset: u64) -> std::io::Result<()> {
        while !data.is_empty() {
            let written = file.seek_write(data, offset)?;

            if written == 0 {
                return Err(std::io::ErrorKind::WriteZero.into());
            }

            data = &data[written..];
            offset += u64::try_from(written).unwrap_or(u64::MAX);
        }

        Ok(())
    }

    pub fn with_created(
        times: std::fs::FileTimes,
        created: Option<std::time::SystemTime>,
    ) -> std::fs::FileTimes {
        match created {
            Some(created) => times.set_created(created),
            None => times,
        }
    }

    pub fn open_attributes(path: &Path) -> std::io::Result<File> {
        File::options()
            .access_mode(WRITE_ATTRIBUTES)
            .custom_flags(BACKUP_SEMANTICS)
            .open(path)
    }

    /// `MoveFileEx` without `MOVEFILE_REPLACE_EXISTING` refuses atomically,
    /// but std's rename always passes it; a file is claimed with a hard link
    /// instead, and a directory checked first.
    pub fn rename_no_replace(from: &Path, to: &Path) -> std::io::Result<()> {
        if std::fs::symlink_metadata(from)?.is_dir() {
            if std::fs::symlink_metadata(to).is_ok() {
                return Err(std::io::ErrorKind::AlreadyExists.into());
            }

            return std::fs::rename(from, to);
        }

        std::fs::hard_link(from, to)?;
        std::fs::remove_file(from)
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use std::fs::File;
    use std::path::Path;

    pub fn write_all_at(_: &File, _: &[u8], _: u64) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    pub const fn with_created(
        times: std::fs::FileTimes,
        _: Option<std::time::SystemTime>,
    ) -> std::fs::FileTimes {
        times
    }

    pub fn open_attributes(path: &Path) -> std::io::Result<File> {
        File::open(path)
    }

    pub fn rename_no_replace(_: &Path, _: &Path) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}
