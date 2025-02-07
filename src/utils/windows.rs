pub mod time {

    const WINDOWS_EPOCH_OFFSET: u64 = 11_644_473_600 * 10_000_000; // 1601 to 1970 in 100-ns intervals

    #[derive(Debug, Clone, Copy)]
    pub struct File(u64);

    impl From<std::time::SystemTime> for File {
        fn from(st: std::time::SystemTime) -> Self {
            // Calculate duration since UNIX epoch
            let duration = st
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::new(0, 0));

            // Convert to 100-nanosecond intervals
            let total_100ns = (duration.as_secs() * 10_000_000)
                + (u64::from(duration.subsec_nanos()) / 100)
                + WINDOWS_EPOCH_OFFSET;

            Self(total_100ns)
        }
    }

    impl From<File> for u64 {
        fn from(ft: File) -> Self {
            ft.0
        }
    }

    impl From<u64> for File {
        fn from(num: u64) -> Self {
            Self(num)
        }
    }
}
