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

    /// The time `ticks` names, or `None` for zero, which a client sends for a
    /// time it leaves alone, and for anything before 1970.
    pub fn from_file_time(ticks: u64) -> Option<std::time::SystemTime> {
        let since = ticks.checked_sub(WINDOWS_EPOCH_OFFSET)?;

        (ticks != 0).then(|| {
            std::time::UNIX_EPOCH
                + std::time::Duration::from_secs(since / 10_000_000)
                + std::time::Duration::from_nanos((since % 10_000_000) * 100)
        })
    }
}
