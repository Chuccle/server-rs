//! Hit/miss counters.
//!
//! A "hit" means the response was assembled without touching the filesystem -
//! see [`crate::utils::cache::Origin`]. Both counters compile away entirely
//! when the `stats` feature is off.

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

    /// Record exactly one outcome per request.
    #[cfg(feature = "stats")]
    #[inline]
    pub fn record(&self, origin: crate::utils::cache::Origin) {
        match origin {
            crate::utils::cache::Origin::Cache => self.increment_hits(),
            crate::utils::cache::Origin::Filesystem => self.increment_misses(),
        }
    }

    /// Record exactly one outcome per request.
    #[cfg(not(feature = "stats"))]
    #[inline]
    pub const fn record(&self, origin: crate::utils::cache::Origin) {
        let _ = (self, origin);
    }

    #[cfg(feature = "stats")]
    pub fn increment_hits(&self) {
        self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(not(feature = "stats"))]
    pub const fn increment_hits(&self) {
        let _ = self;
    }

    #[cfg(feature = "stats")]
    pub fn increment_misses(&self) {
        self.misses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(not(feature = "stats"))]
    pub const fn increment_misses(&self) {
        let _ = self;
    }

    #[cfg(feature = "stats")]
    pub fn get(&self) -> (u64, u64) {
        (
            self.hits.load(std::sync::atomic::Ordering::Relaxed),
            self.misses.load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}
