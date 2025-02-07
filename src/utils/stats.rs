#[derive(Default)]
pub struct Cache {
    #[cfg(feature = "stats")]
    hits: std::sync::atomic::AtomicU64,
    #[cfg(feature = "stats")]
    misses: std::sync::atomic::AtomicU64,
}

impl Cache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment_hits(&self) {
        #[cfg(feature = "stats")]
        self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn increment_misses(&self) {
        #[cfg(feature = "stats")]
        self.misses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(feature = "stats")]
    pub fn get(&self) -> (u64, u64) {
        (
            self.hits.load(std::sync::atomic::Ordering::Relaxed),
            self.misses.load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}
