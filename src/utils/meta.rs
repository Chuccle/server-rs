//! The flat metadata record every cache layer stores.

/// One filesystem entry, reduced to the five scalars the wire schema carries.
///
/// `Copy` and free of pointers on purpose: directory children are held in a
/// single `Box<[RawMeta]>`, so a listing walk is a linear scan over 40-byte
/// rows instead of a pointer chase through per-entry allocations.
///
/// Timestamps are Windows `FILETIME` ticks (100 ns since 1601) because that is
/// what the schema declares; see [`crate::utils::windows::time`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RawMeta {
    pub size: u64,
    pub created: u64,
    pub modified: u64,
    pub accessed: u64,
    pub is_dir: bool,
}

impl RawMeta {
    #[inline]
    pub fn from_std(metadata: &std::fs::Metadata) -> Self {
        Self {
            size: metadata.len(),
            created: file_time(metadata.created()),
            modified: file_time(metadata.modified()),
            accessed: file_time(metadata.accessed()),
            is_dir: metadata.is_dir(),
        }
    }
}

/// Platforms that cannot report a timestamp (`created` on most Linux
/// filesystems) fall back to "now", matching the previous behaviour.
#[inline]
fn file_time(time: std::io::Result<std::time::SystemTime>) -> u64 {
    use crate::utils::windows::time::IntoFileTime as _;

    time.unwrap_or_else(|_| std::time::SystemTime::now())
        .into_file_time()
}
