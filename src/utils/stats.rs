#[derive(Default)]
pub struct CacheStats {
    #[cfg(feature = "cache_stats")]
    hits: std::sync::atomic::AtomicU64,
    #[cfg(feature = "cache_stats")]
    misses: std::sync::atomic::AtomicU64,
}

impl CacheStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment_hits(&self) {
        #[cfg(feature = "cache_stats")]
        self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn increment_misses(&self) {
        #[cfg(feature = "cache_stats")]
        self.misses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(feature = "cache_stats")]
    pub fn get_stats(&self) -> (u64, u64) {
        (
            self.hits.load(std::sync::atomic::Ordering::Relaxed),
            self.misses.load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}
