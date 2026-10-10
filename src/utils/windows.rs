pub mod time {

    pub const WINDOWS_EPOCH_OFFSET: u64 = 11_644_473_600 * 10_000_000; // 1601 to 1970 in 100-ns intervals

    pub trait IntoFileTime {
        fn into_file_time(self) -> u64;
    }

    impl IntoFileTime for std::time::SystemTime {
        fn into_file_time(self) -> u64 {
            let duration = self
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::new(0, 0));

            (duration.as_secs() * 10_000_000)
                + (u64::from(duration.subsec_nanos()) / 100)
                + WINDOWS_EPOCH_OFFSET
        }
    }
}

/// Directory enumeration through an open handle.
///
/// cap-std lists a directory by asking for the handle's final path and
/// handing that to `std::fs::read_dir`, which loses a UNC root, normalises a
/// trailing dot or space onto a sibling, and lists whatever the path names by
/// then rather than the directory that was opened. Asking the handle itself
/// for its entries has none of those problems, and returns each child's
/// metadata with its name.
#[cfg(windows)]
pub(crate) mod directory {
    use crate::utils::meta::RawMeta;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::ERROR_NO_MORE_FILES;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ID_BOTH_DIR_INFO,
        FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo, GetFileInformationByHandleEx,
    };

    /// Bytes asked for per call. Entries are 8-byte aligned, so the buffer is
    /// held as `u64`s.
    const BUFFER_WORDS: usize = 8192;

    /// Reparse tags with this bit set are name surrogates (symlinks and
    /// junctions), which std reports as symlinks rather than directories.
    const NAME_SURROGATE: u32 = 0x2000_0000;

    /// Every child of `directory` with a UTF-8 name, and its metadata, not
    /// following symlinks.
    ///
    /// The handle stays open while `directory` is borrowed, and the system
    /// writes no more than `size` bytes into `buffer`, which it fills with
    /// whole records.
    pub fn children(directory: &cap_std::fs::Dir) -> std::io::Result<Vec<(Box<str>, RawMeta)>> {
        let mut buffer = vec![0u64; BUFFER_WORDS];
        let size = u32::try_from(BUFFER_WORDS * size_of::<u64>()).unwrap_or(u32::MAX);
        let mut class = FileIdBothDirectoryRestartInfo;
        let mut children = Vec::new();

        loop {
            let filled = unsafe {
                GetFileInformationByHandleEx(
                    directory.as_raw_handle(),
                    class,
                    buffer.as_mut_ptr().cast(),
                    size,
                )
            };

            if filled == 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == i32::try_from(ERROR_NO_MORE_FILES).ok() {
                    return Ok(children);
                }
                return Err(error);
            }

            class = FileIdBothDirectoryInfo;
            unsafe { parse(buffer.as_ptr().cast(), &mut children) };
        }
    }

    /// Decode one filled buffer of `FILE_ID_BOTH_DIR_INFO` records.
    ///
    /// # Safety
    ///
    /// `start` must begin a chain of whole records as the system writes them:
    /// each `NextEntryOffset` bytes after the one before, the last with an
    /// offset of zero, and each followed by `FileNameLength` bytes of name.
    unsafe fn parse(start: *const FILE_ID_BOTH_DIR_INFO, children: &mut Vec<(Box<str>, RawMeta)>) {
        let mut entry = start;

        loop {
            let info = unsafe { entry.read_unaligned() };
            let name = unsafe {
                std::slice::from_raw_parts(
                    std::ptr::addr_of!((*entry).FileName).cast::<u16>(),
                    usize::try_from(info.FileNameLength).unwrap_or(0) / size_of::<u16>(),
                )
            };

            if let Some(child) = child(&info, name) {
                children.push(child);
            }

            if info.NextEntryOffset == 0 {
                return;
            }

            entry = unsafe { entry.byte_add(usize::try_from(info.NextEntryOffset).unwrap_or(0)) };
        }
    }

    /// The schema carries UTF-8 names, and a name that is not one could not
    /// be addressed through a query string either.
    fn child(info: &FILE_ID_BOTH_DIR_INFO, name: &[u16]) -> Option<(Box<str>, RawMeta)> {
        let name = String::from_utf16(name).ok()?;

        if name == "." || name == ".." {
            return None;
        }

        let reparse = info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        let surrogate = reparse && info.EaSize & NAME_SURROGATE != 0;

        Some((
            name.into_boxed_str(),
            RawMeta {
                size: u64::try_from(info.EndOfFile).unwrap_or(0),
                created: ticks(info.CreationTime),
                modified: ticks(info.LastWriteTime),
                accessed: ticks(info.LastAccessTime),
                is_dir: info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 && !surrogate,
            },
        ))
    }

    /// The same value [`super::time::IntoFileTime`] gives for this time read
    /// through std, which clamps anything before 1970 to 1970.
    fn ticks(time: i64) -> u64 {
        u64::try_from(time)
            .unwrap_or(0)
            .max(super::time::WINDOWS_EPOCH_OFFSET)
    }
}
