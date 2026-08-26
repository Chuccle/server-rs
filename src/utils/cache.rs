//! The server's cache tier.
//!
//! # Shape
//!
//! Three caches, each answering a question the others cannot:
//!
//! * `resolved` - request key to canonical path. This is the one that removes
//!   `canonicalize` from the hot path. The previous design keyed its caches by
//!   canonical path, so every request had to pay a `canonicalize` syscall
//!   *before* it could even look for a cache hit.
//! * `dirs` - canonical directory path to a scanned [`DirNode`], holding the
//!   listing already encoded as `FlatBuffers`.
//! * `contents` - canonical file path to its bytes, for files small enough to
//!   hold resident.
//!
//! There is deliberately no per-entry metadata cache. A directory's listing
//! already contains every child's metadata, so single-entry lookups read out of
//! the parent's node instead of storing the same facts under a second key.
//!
//! # Cost of a warm request
//!
//! Two hash lookups and a refcount bump. No syscalls, no blocking-pool hop, no
//! re-serialisation, no allocation proportional to directory size.
//!
//! # Staleness
//!
//! Successful resolutions are cached; failures never are, so a rejected path is
//! re-validated from scratch every time. The filesystem watcher drops
//! resolutions whose canonical path sits at or under anything created, removed
//! or renamed, and every entry is additionally bounded by TTL.

use crate::error::AppError;
// See `crate::utils::hash` for why these caches do not use the default hasher.
use crate::utils::hash::RandomState;
use crate::utils::{flat, meta::RawMeta, path};
use bytes::Bytes;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Whether a response was assembled without touching the filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Cache,
    Filesystem,
}

impl Origin {
    /// A response only counts as a hit if *every* lookup behind it was one.
    ///
    /// `#[must_use]` because dropping the result silently mis-records the
    /// combined outcome as whichever side happened to be evaluated last.
    #[must_use]
    #[inline]
    pub fn and(self, other: Self) -> Self {
        if self == Self::Cache && other == Self::Cache {
            Self::Cache
        } else {
            Self::Filesystem
        }
    }
}

/// Cache sizing.
///
/// Budgets are in bytes rather than entry counts: a listing for a 50k-file
/// directory and one for an empty directory are not the same thing to hold, and
/// an entry-count bound lets the former blow up the heap.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub time_to_live: std::time::Duration,
    pub time_to_idle: std::time::Duration,
    /// Budget for resolved paths and directory listings.
    pub metadata_bytes: u64,
    /// Budget for resident file contents.
    pub content_bytes: u64,
    /// Files above this size are streamed from disk instead of held resident.
    pub max_resident_file_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            time_to_live: std::time::Duration::from_mins(5),
            time_to_idle: std::time::Duration::from_mins(1),
            metadata_bytes: 256 * 1024 * 1024,
            content_bytes: 512 * 1024 * 1024,
            max_resident_file_bytes: 8 * 1024 * 1024,
        }
    }
}

/// `u32` offsets are widened here rather than with `as`, which keeps the
/// truncation lints happy. On a 64-bit target it compiles to nothing.
#[inline]
fn widen(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// A scanned directory, laid out for the only two questions asked of it: "give
/// me the whole listing" and "give me one child's metadata".
///
/// # Layout
///
/// Nothing here is a per-entry allocation. Names are one contiguous string
/// addressed by a compressed-row offset array, and the lookup index is a dense
/// sorted `u64` array so that a binary search walks a handful of sequential
/// cache lines instead of chasing a string pointer at every probe.
///
/// `metas` stays row-major rather than being split field-by-field, because both
/// of its access patterns want whole rows: a child lookup reads exactly one
/// [`RawMeta`] (a single cache line), and the listing that reads every field of
/// every row is encoded once here and never walked again. Splitting it would
/// turn one cache line into four.
pub struct DirNode {
    listing: Bytes,
    own: RawMeta,

    /// Child names concatenated in name order.
    names: Box<str>,
    /// `names[offsets[i]..offsets[i + 1]]` is child `i`. Length is `n + 1`.
    offsets: Box<[u32]>,
    /// Child metadata, in the same order as `offsets`.
    metas: Box<[RawMeta]>,

    /// Child name hashes in ascending order - the array the search actually
    /// probes.
    hashes: Box<[u64]>,
    /// `slots[i]` is the child index whose name hashes to `hashes[i]`.
    slots: Box<[u32]>,

    weight: u32,
}

/// Below this many entries, thread-spawn overhead costs more than the
/// syscalls it would save. Chosen from measurement, not a guess: see
/// `dir_node/scan` in `benches/hot_path.rs` and the note in `BENCHMARKING.md`.
const PARALLEL_STAT_THRESHOLD: usize = 512;

/// Entries per worker below which another worker isn't worth starting.
const MIN_CHUNK: usize = 128;

/// `DirEntry::metadata` is one `statx` each, and for a large directory that
/// dominates a cold scan - independent syscalls on unrelated files, run one at
/// a time on a single blocking-pool thread. Fanning them out over
/// `std::thread::scope` lets the kernel service them concurrently instead.
///
/// Plain threads rather than a `rayon`/tokio dependency: this runs once per
/// cache miss, already inside `spawn_blocking`, and needs nothing beyond
/// "run N closures, join them" - not a dependency's work-stealing scheduler.
fn stat_children(entries: &[std::fs::DirEntry]) -> Vec<(Box<str>, RawMeta)> {
    fn stat_one(entry: &std::fs::DirEntry) -> Option<(Box<str>, RawMeta)> {
        // The schema carries UTF-8 names, and a non-UTF-8 name could not be
        // addressed through a query string either.
        let name = entry.file_name().into_string().ok()?;
        let metadata = entry.metadata().ok()?;

        Some((name.into_boxed_str(), RawMeta::from_std(&metadata)))
    }

    // Below the threshold, stay on a single pass with no further syscalls:
    // `available_parallelism` is `sched_getaffinity` under the hood, and
    // under this environment's virtualization that alone was measured to
    // cost more than scanning a small directory outright (see
    // `dir_node/scan` before/after in `BENCHMARKING.md`).
    if entries.len() < PARALLEL_STAT_THRESHOLD {
        return entries.iter().filter_map(stat_one).collect();
    }

    let workers = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let chunk_count = (entries.len() / MIN_CHUNK).clamp(1, workers);

    if chunk_count <= 1 {
        return entries.iter().filter_map(stat_one).collect();
    }

    let chunk_size = entries.len().div_ceil(chunk_count);

    std::thread::scope(|scope| {
        entries
            .chunks(chunk_size)
            .map(|chunk| scope.spawn(move || chunk.iter().filter_map(stat_one).collect::<Vec<_>>()))
            .collect::<Vec<_>>()
            .into_iter()
            // A worker can only fail by panicking, which already unwinds the
            // process in a `spawn_blocking` context - nothing here downgrades
            // that into a silently dropped directory chunk.
            .flat_map(|worker| worker.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect()
    })
}

impl DirNode {
    /// Read a directory and encode everything the hot path will ever need.
    ///
    /// Blocking: one `metadata` call plus one `read_dir` walk. The sort and the
    /// listing encode happen here so that no request ever pays for them.
    ///
    /// # Errors
    ///
    /// [`AppError::NotFound`] if `path` is not a directory, plus the usual I/O
    /// mappings if it cannot be read.
    pub fn scan(path: &Path) -> Result<Self, AppError> {
        let own_metadata = std::fs::metadata(path)?;

        if !own_metadata.is_dir() {
            return Err(AppError::NotFound);
        }

        let entries: Vec<std::fs::DirEntry> = std::fs::read_dir(path)?
            .filter_map(std::result::Result::ok)
            .collect();

        let mut children = stat_children(&entries);

        children.sort_unstable_by(|left, right| left.0.cmp(&right.0));

        let listing = flat::listing(&children);

        let mut names = String::with_capacity(children.iter().map(|(name, _)| name.len()).sum());
        let mut offsets = Vec::with_capacity(children.len() + 1);
        let mut metas = Vec::with_capacity(children.len());
        let mut index = Vec::with_capacity(children.len());

        offsets.push(0);

        for (position, (name, meta)) in children.iter().enumerate() {
            names.push_str(name);
            offsets.push(u32::try_from(names.len()).unwrap_or(u32::MAX));
            metas.push(*meta);
            index.push((
                crate::utils::hash::name(name),
                u32::try_from(position).unwrap_or(u32::MAX),
            ));
        }

        // Sorting by hash lets the lookup binary-search a dense scalar array.
        // Names stay in name order so the listing above is stable.
        index.sort_unstable_by_key(|&(hash, _)| hash);

        let mut hashes = Vec::with_capacity(index.len());
        let mut slots = Vec::with_capacity(index.len());
        for (hash, position) in index {
            hashes.push(hash);
            slots.push(position);
        }

        let footprint = listing.len()
            + names.len()
            + offsets.len() * size_of::<u32>()
            + metas.len() * size_of::<RawMeta>()
            + hashes.len() * size_of::<u64>()
            + slots.len() * size_of::<u32>();

        Ok(Self {
            listing,
            own: RawMeta::from_std(&own_metadata),
            names: names.into_boxed_str(),
            offsets: offsets.into_boxed_slice(),
            metas: metas.into_boxed_slice(),
            hashes: hashes.into_boxed_slice(),
            slots: slots.into_boxed_slice(),
            weight: u32::try_from(footprint).unwrap_or(u32::MAX),
        })
    }

    /// The pre-encoded listing. Cloning a [`Bytes`] is a refcount bump.
    #[inline]
    pub fn listing(&self) -> Bytes {
        self.listing.clone()
    }

    /// This directory's own metadata.
    #[inline]
    pub const fn own(&self) -> RawMeta {
        self.own
    }

    /// Metadata for one child, by its exact on-disk name.
    ///
    /// Callers pass the name taken from a canonical path, which already carries
    /// the on-disk spelling, so an exact comparison is correct even on
    /// case-insensitive filesystems.
    pub fn child(&self, name: &str) -> Option<RawMeta> {
        let wanted = crate::utils::hash::name(name);
        let mut probe = self.hashes.partition_point(|hash| *hash < wanted);

        // Equal hashes sit next to each other, so a collision costs a short
        // forward scan. The name comparison is what settles it.
        while self.hashes.get(probe) == Some(&wanted) {
            let child = widen(*self.slots.get(probe)?);

            if self.name_of(child) == Some(name) {
                return self.metas.get(child).copied();
            }

            probe += 1;
        }

        None
    }

    fn name_of(&self, child: usize) -> Option<&str> {
        let start = widen(*self.offsets.get(child)?);
        let end = widen(*self.offsets.get(child + 1)?);

        self.names.get(start..end)
    }
}

/// A file held resident in memory, with its response headers pre-rendered so
/// that serving it is a handful of `HeaderValue` refcount bumps.
pub struct FileNode {
    pub data: Bytes,
    pub len: u64,
    /// Truncated to whole seconds so it compares cleanly against an
    /// `If-Modified-Since`, which only has second granularity.
    pub modified: Option<std::time::SystemTime>,
    pub content_type: axum::http::HeaderValue,
    pub last_modified: Option<axum::http::HeaderValue>,
    pub etag: Option<axum::http::HeaderValue>,
}

/// What the file endpoint should do with a resolved path.
#[derive(Clone)]
pub enum Content {
    /// Small enough to answer entirely from memory.
    Resident(Arc<FileNode>),
    /// Too large to hold resident; stream it off disk. Cached as a decision so
    /// the size check is not repeated on every request.
    Streamed,
}

type PathCache<V> = moka::future::Cache<PathBuf, V, RandomState>;
type KeyCache<V> = moka::future::Cache<String, V, RandomState>;

pub struct Store {
    base: PathBuf,
    config: Config,
    resolved: KeyCache<Arc<Path>>,
    dirs: PathCache<Arc<DirNode>>,
    contents: PathCache<Content>,
}

/// Rough fixed cost of one resolution entry: two allocations plus the cache's
/// own bookkeeping.
const RESOLVED_OVERHEAD: u32 = 96;

/// Nominal weight of a "stream this one" decision, which holds no data.
const STREAMED_WEIGHT: u32 = 64;

impl Store {
    /// # Errors
    ///
    /// Propagates the I/O error if `base` cannot be canonicalised. Every
    /// containment check downstream compares against the canonical form, so
    /// this has to happen exactly once, here.
    pub fn new(base: &Path, config: Config) -> std::io::Result<Self> {
        let base = std::fs::canonicalize(base)?;

        let resolved = moka::future::Cache::builder()
            .max_capacity(config.metadata_bytes)
            .weigher(|key: &String, value: &Arc<Path>| {
                let bytes = key.len() + value.as_os_str().len();
                u32::try_from(bytes)
                    .unwrap_or(u32::MAX)
                    .saturating_add(RESOLVED_OVERHEAD)
            })
            .time_to_live(config.time_to_live)
            .time_to_idle(config.time_to_idle)
            .build_with_hasher(RandomState::default());

        let dirs = moka::future::Cache::builder()
            .max_capacity(config.metadata_bytes)
            .weigher(|_: &PathBuf, value: &Arc<DirNode>| value.weight)
            .time_to_live(config.time_to_live)
            .time_to_idle(config.time_to_idle)
            .build_with_hasher(RandomState::default());

        let contents = moka::future::Cache::builder()
            .max_capacity(config.content_bytes)
            .weigher(|_: &PathBuf, value: &Content| match value {
                Content::Resident(node) => u32::try_from(node.data.len()).unwrap_or(u32::MAX),
                Content::Streamed => STREAMED_WEIGHT,
            })
            .time_to_live(config.time_to_live)
            .time_to_idle(config.time_to_idle)
            .build_with_hasher(RandomState::default());

        Ok(Self {
            base,
            config,
            resolved,
            dirs,
            contents,
        })
    }

    #[inline]
    pub fn base(&self) -> &Path {
        &self.base
    }

    /// Serialised listing for a directory.
    ///
    /// # Errors
    ///
    /// Traversal, missing path, or an unreadable directory.
    pub async fn directory_listing(&self, raw: &str) -> Result<(Bytes, Origin), AppError> {
        let key = path::normalize(raw)?;
        let (canonical, resolved) = self.resolve(&key).await?;
        let (node, scanned) = self.dir_node(&canonical).await?;

        Ok((node.listing(), resolved.and(scanned)))
    }

    /// Serialised metadata for a single entry.
    ///
    /// Read out of the parent directory's node rather than a cache of its own.
    ///
    /// # Errors
    ///
    /// Traversal, missing path, or permission denied.
    pub async fn entry_metadata(&self, raw: &str) -> Result<(Bytes, Origin), AppError> {
        let key = path::normalize(raw)?;
        let (canonical, resolved) = self.resolve(&key).await?;

        // The served root has no parent inside the tree, so it answers for
        // itself out of its own node.
        if *canonical == *self.base {
            let (node, scanned) = self.dir_node(&canonical).await?;
            return Ok((flat::entry(&node.own()), resolved.and(scanned)));
        }

        if let Some(parent) = canonical.parent()
            && let Some(name) = canonical.file_name().and_then(std::ffi::OsStr::to_str)
            && let Ok((node, scanned)) = self.dir_node(parent).await
            && let Some(meta) = node.child(name)
        {
            return Ok((flat::entry(&meta), resolved.and(scanned)));
        }

        // Either the parent could not be listed, or the entry appeared after it
        // was scanned and the watcher has not caught up yet. Stat directly
        // rather than hide a readable entry behind an unreadable or stale
        // parent.
        let target = canonical.to_path_buf();
        let metadata = tokio::task::spawn_blocking(move || std::fs::metadata(target)).await??;

        Ok((
            flat::entry(&RawMeta::from_std(&metadata)),
            Origin::Filesystem,
        ))
    }

    /// Resolve a file request and decide how to serve it.
    ///
    /// # Errors
    ///
    /// Traversal, missing path, or permission denied.
    pub async fn file_content(&self, raw: &str) -> Result<(Arc<Path>, Content, Origin), AppError> {
        let key = path::normalize(raw)?;
        let (canonical, resolved) = self.resolve(&key).await?;

        if let Some(content) = self.contents.get(&*canonical).await {
            return Ok((canonical, content, resolved));
        }

        let cache_key = canonical.to_path_buf();
        let load_path = cache_key.clone();
        let limit = self.config.max_resident_file_bytes;

        let content = self
            .contents
            .try_get_with(cache_key, async move {
                tokio::task::spawn_blocking(move || load_content(&load_path, limit))
                    .await
                    .map_err(AppError::from)?
            })
            .await?;

        Ok((canonical, content, Origin::Filesystem))
    }

    /// Request key to canonical path, coalescing concurrent cold lookups so a
    /// thundering herd costs one `canonicalize` rather than one each.
    ///
    /// Only successes are cached, which keeps an "allowed" verdict from
    /// outliving the symlink topology that justified it.
    async fn resolve(&self, key: &str) -> Result<(Arc<Path>, Origin), AppError> {
        if let Some(canonical) = self.resolved.get(key).await {
            return Ok((canonical, Origin::Cache));
        }

        let base = self.base.clone();
        let owned = key.to_owned();
        let resolve_key = owned.clone();

        let canonical = self
            .resolved
            .try_get_with(owned, async move {
                let resolved = tokio::task::spawn_blocking(move || {
                    path::resolve_blocking(&base, &resolve_key)
                })
                .await??;

                Ok::<Arc<Path>, AppError>(Arc::from(resolved))
            })
            .await?;

        Ok((canonical, Origin::Filesystem))
    }

    async fn dir_node(&self, canonical: &Path) -> Result<(Arc<DirNode>, Origin), AppError> {
        if let Some(node) = self.dirs.get(canonical).await {
            return Ok((node, Origin::Cache));
        }

        let cache_key = canonical.to_path_buf();
        let scan_path = cache_key.clone();

        let node = self
            .dirs
            .try_get_with(cache_key, async move {
                let node = tokio::task::spawn_blocking(move || DirNode::scan(&scan_path)).await??;

                Ok::<Arc<DirNode>, AppError>(Arc::new(node))
            })
            .await?;

        Ok((node, Origin::Filesystem))
    }

    /// Drop everything. Used when the watcher reports it lost track of events.
    pub fn invalidate_all(&self) {
        self.resolved.invalidate_all();
        self.dirs.invalidate_all();
        self.contents.invalidate_all();
    }

    /// A file's bytes changed but its position in the tree did not: drop its
    /// contents and the parent listing that quotes its size and timestamps.
    /// Resolutions stay valid, so this is O(1) and leaves the hot path warm.
    pub async fn invalidate_content(&self, path: &Path) {
        self.contents.invalidate(path).await;

        if let Some(parent) = path.parent() {
            self.dirs.invalidate(parent).await;
        }
    }

    /// The tree itself moved. Renames and directory removals relocate whole
    /// subtrees, so anything that resolved at or *through* one of `roots` has to
    /// go - including resolutions, which can only be matched on the canonical
    /// path they produced, since their keys are request strings.
    pub async fn invalidate_subtree(&self, roots: Vec<PathBuf>) {
        for root in &roots {
            self.dirs.invalidate(root).await;
            self.contents.invalidate(root).await;

            if let Some(parent) = root.parent() {
                self.dirs.invalidate(parent).await;
            }
        }

        // `invalidate_entries_if` would do this same prefix sweep, but
        // opting into it (`support_invalidation_closures`) taxes every single
        // `get()` on every cache tier - measured at 5-13% on the warm path,
        // to support a predicate call that only ever runs here, on the rare,
        // off-hot-path event of a directory actually moving. `iter()` needs
        // no such opt-in: same sweep, paid only when a structural event
        // actually happens.
        for (key, _) in &self.dirs {
            if roots.iter().any(|root| key.starts_with(root.as_path())) {
                self.dirs.invalidate(&*key).await;
            }
        }

        for (key, _) in &self.contents {
            if roots.iter().any(|root| key.starts_with(root.as_path())) {
                self.contents.invalidate(&*key).await;
            }
        }

        for (key, value) in &self.resolved {
            if roots.iter().any(|root| value.starts_with(root)) {
                self.resolved.invalidate(&*key).await;
            }
        }
    }
}

/// Probes and targeted invalidation the server itself never needs, but that
/// tests use to assert on cache state directly.
#[cfg(test)]
impl Store {
    /// Forget one directory's listing.
    pub async fn invalidate_directory(&self, canonical: &Path) {
        self.dirs.invalidate(canonical).await;
    }

    /// Whether a directory listing is currently resident.
    ///
    /// Unlike a `get`, this does not count as an access, so it will not reset
    /// the entry's idle timer.
    pub fn has_directory(&self, canonical: &Path) -> bool {
        self.dirs.contains_key(canonical)
    }

    /// Whether a file's contents are currently resident.
    pub fn has_content(&self, canonical: &Path) -> bool {
        self.contents.contains_key(canonical)
    }

    /// The `time_to_live`/`time_to_idle` each cache tier was actually built
    /// with, for asserting that [`Config`] reaches every one of them.
    ///
    /// This is the only thing about expiration this crate can test: `moka`
    /// reads `std::time::Instant::now()` internally rather than through
    /// `tokio::time`, so its clock is not mockable from outside the crate, and
    /// actually observing an expiry deterministically is not possible without
    /// a real sleep. Configuration wiring is instant and fully within our
    /// control, so that is what gets asserted on.
    pub fn policies(&self) -> [moka::policy::Policy; 3] {
        [
            self.resolved.policy(),
            self.dirs.policy(),
            self.contents.policy(),
        ]
    }
}

/// Open once, then decide from the handle's own metadata whether to hold the
/// file resident. Reading metadata off the open handle rather than the path
/// saves a syscall and closes the window where the path could change underneath
/// us.
fn load_content(path: &Path, limit: u64) -> Result<Content, AppError> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;

    if metadata.is_dir() {
        return Err(AppError::NotFound);
    }

    if metadata.len() > limit {
        return Ok(Content::Streamed);
    }

    let mut data = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.read_to_end(&mut data)?;

    // Trust what was actually read over what the metadata claimed.
    let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
    let modified = metadata.modified().ok().map(truncate_to_seconds);

    let content_type = axum::http::HeaderValue::from_str(
        mime_guess::from_path(path).first_or_octet_stream().as_ref(),
    )
    .unwrap_or_else(|_| axum::http::HeaderValue::from_static("application/octet-stream"));

    let last_modified = modified
        .map(httpdate::fmt_http_date)
        .and_then(|date| axum::http::HeaderValue::from_str(&date).ok());

    // Strong validator over the two things that change when the bytes do.
    let ticks = RawMeta::from_std(&metadata).modified;
    let etag = axum::http::HeaderValue::from_str(&format!("\"{len:x}-{ticks:x}\"")).ok();

    Ok(Content::Resident(Arc::new(FileNode {
        data: Bytes::from(data),
        len,
        modified,
        content_type,
        last_modified,
        etag,
    })))
}

fn truncate_to_seconds(time: std::time::SystemTime) -> std::time::SystemTime {
    time.duration_since(std::time::UNIX_EPOCH)
        .map_or(time, |since| {
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(since.as_secs())
        })
}

/// Translate a debounced batch of filesystem events into cache invalidations.
///
/// Events are split by what they actually invalidate. Content changes are the
/// common case and stay O(1); only structural changes - which can move whole
/// subtrees - pay for a predicate sweep.
pub async fn handle_fs_events(events: &[notify_debouncer_full::DebouncedEvent], store: &Store) {
    use notify_debouncer_full::notify::EventKind;
    use notify_debouncer_full::notify::event::ModifyKind;

    let mut content_changes: HashSet<PathBuf> = HashSet::new();
    let mut structural: Vec<PathBuf> = Vec::new();

    for event in events {
        crate::log_trace!("Processing file watch event: {:?}", event);

        if event.need_rescan() {
            crate::log_warn!("File watch rescan flag received, dropping all cached state");
            store.invalidate_all();
            return;
        }

        match event.kind {
            EventKind::Modify(ModifyKind::Data(_) | ModifyKind::Metadata(_)) => {
                content_changes.extend(event.paths.iter().cloned());
            }

            // Creates, removes and renames all change what a path *means*, and
            // a rename event carries both the old and the new path.
            EventKind::Create(_) | EventKind::Remove(_) | EventKind::Modify(_) => {
                structural.extend(event.paths.iter().cloned());
            }

            _ => {
                crate::log_trace!("Unhandled event type: {:?}", event.kind);
            }
        }
    }

    for path in &content_changes {
        store.invalidate_content(path).await;
    }

    if !structural.is_empty() {
        store.invalidate_subtree(structural).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a directory and scan it, so the index under test is the one the
    /// server would actually hold.
    fn scanned(names: &[&str], dirs: &[&str]) -> (tempfile::TempDir, DirNode) {
        let temp = tempfile::tempdir().expect("tempdir");

        for name in names {
            std::fs::write(temp.path().join(name), *name).expect("write");
        }
        for name in dirs {
            std::fs::create_dir(temp.path().join(name)).expect("mkdir");
        }

        let node = DirNode::scan(temp.path()).expect("scan");
        (temp, node)
    }

    #[test]
    fn every_child_is_findable_with_its_own_metadata() {
        let files = ["a.txt", "b.txt", "zzz.bin", "with space.md", "файл.txt"];
        let (_temp, node) = scanned(&files, &["sub", "another"]);

        for name in files {
            let meta = node.child(name).unwrap_or_else(|| panic!("missing {name}"));
            assert!(!meta.is_dir, "{name} should be a file");
            // Each file was written with its own name as contents.
            let expected = u64::try_from(name.len()).expect("length fits");
            assert_eq!(meta.size, expected, "wrong size for {name}");
        }

        for name in ["sub", "another"] {
            let meta = node.child(name).unwrap_or_else(|| panic!("missing {name}"));
            assert!(meta.is_dir, "{name} should be a directory");
        }
    }

    #[test]
    fn absent_names_miss_rather_than_returning_a_neighbour() {
        // A hash-ordered index has no notion of "nearby", so a miss must not
        // land on whatever happens to sit at the partition point.
        let (_temp, node) = scanned(&["a.txt", "b.txt"], &[]);

        for name in ["", "a", "a.tx", "a.txtt", "c.txt", "A.TXT", "zzz"] {
            assert!(node.child(name).is_none(), "{name:?} should not be found");
        }
    }

    #[test]
    fn a_directory_with_many_children_stays_consistent() {
        // Enough entries that the binary search does real work, and enough to
        // shake out an off-by-one in the offset array.
        let names: Vec<String> = (0..512).map(|i| format!("entry_{i:04}.dat")).collect();
        let borrowed: Vec<&str> = names.iter().map(String::as_str).collect();
        let (_temp, node) = scanned(&borrowed, &[]);

        for name in &names {
            assert!(node.child(name).is_some(), "missing {name}");
        }
        assert!(node.child("entry_9999.dat").is_none());
    }

    #[test]
    fn the_empty_directory_has_no_children() {
        let (_temp, node) = scanned(&[], &[]);

        assert!(node.child("anything").is_none());
        assert!(node.child("").is_none());
        assert!(node.own().is_dir);
    }

    #[test]
    fn scanning_a_file_is_not_found() {
        let temp = tempfile::tempdir().expect("tempdir");
        let file = temp.path().join("plain.txt");
        std::fs::write(&file, "x").expect("write");

        // `DirNode` has no `PartialEq`, so match on the error rather than the
        // whole `Result`.
        match DirNode::scan(&file) {
            Err(error) => assert_eq!(error, AppError::NotFound),
            Ok(_) => panic!("scanning a plain file should not produce a listing"),
        }
    }

    #[test]
    fn configured_durations_reach_every_cache_tier() {
        let temp = tempfile::tempdir().expect("tempdir");

        let config = Config {
            time_to_live: std::time::Duration::from_secs(42),
            time_to_idle: std::time::Duration::from_secs(7),
            ..Config::default()
        };

        let store = Store::new(temp.path(), config).expect("store");

        for policy in store.policies() {
            assert_eq!(policy.time_to_live(), Some(config.time_to_live));
            assert_eq!(policy.time_to_idle(), Some(config.time_to_idle));
        }
    }
}
