pub mod time {

    const WINDOWS_EPOCH_OFFSET: u64 = 11_644_473_600 * 10_000_000; // 1601 to 1970 in 100-ns intervals

    #[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
    pub struct FileTime(u64);

    impl From<std::time::SystemTime> for FileTime {
        fn from(st: std::time::SystemTime) -> Self {
            // Calculate duration since UNIX epoch
            let duration = st
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::new(0, 0));

            // Convert to 100-nanosecond intervals
            let total_100ns = (duration.as_secs() * 10_000_000)
                + (duration.subsec_nanos() as u64 / 100)
                + WINDOWS_EPOCH_OFFSET;

            FileTime(total_100ns)
        }
    }

    impl From<FileTime> for u64 {
        fn from(ft: FileTime) -> u64 {
            ft.0
        }
    }
}
