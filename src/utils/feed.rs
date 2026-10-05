//! The change feed: what the filesystem watcher saw change, numbered, so a
//! client that caches this server's answers can drop exactly what moved
//! instead of expiring everything on a timer.
//!
//! # Contract
//!
//! Every debounced batch of watcher events is one *generation*. A client asks
//! `GET /get_changes?epoch=E&since=G` and gets back, as a `ChangeBatch`, every
//! path that changed after generation `G`, the generation that brings it up
//! to date, and this process's epoch. When it is already up to date the
//! request is held until something changes or [`Config::feed_hold`] passes,
//! whichever is first; an empty batch is the heartbeat.
//!
//! Each path is reported once, under what last happened to it: `created` or
//! `removed` if its existence changed - decided by whether it exists once the
//! batch is in, so a rename reports its old path removed and its new one
//! created - and otherwise `modified`, for bytes or metadata changed in place.
//!
//! `reset` is the answer whenever a precise one is impossible: a different
//! epoch (the server restarted, so nothing the client holds is anchored to
//! anything), a generation older than what is still retained, or a watcher
//! that reported it lost events. A client must then drop everything it cached
//! and start again from the batch's generation.
//!
//! # What a client may conclude
//!
//! Only that an answer read after it applied generation `G` reflects every
//! change the watcher reported up to `G`. That holds because the cache tier
//! bumps [`Feed::begin`] before it invalidates anything and publishes after,
//! and refuses to vouch for a load that a bump overtook - see
//! [`crate::utils::cache::Stamped`]. Changes the watcher has not reported yet
//! (it debounces for two seconds) are not covered by anything.
//!
//! [`Config::feed_hold`]: crate::utils::cache::Config::feed_hold

use crate::generated::blorg_meta_flat as fb;
use bytes::Bytes;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// What happened to a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Modified,
    Created,
    Removed,
}

/// One path the watcher reported, under the generation that reported it.
struct Change {
    generation: u64,
    kind: Kind,
    path: Box<str>,
}

/// The retained history. Everything behind one lock: it is touched once per
/// watcher batch and once per answered poll, never on the request hot path.
struct History {
    changes: VecDeque<Change>,
    /// The newest generation that has lost a change to the retention bound,
    /// or been reset outright. A client behind it cannot be told precisely
    /// what it missed.
    floor: u64,
}

pub struct Feed {
    /// Identifies this process. Generations restart with it, so a client
    /// holding another epoch's generation has nothing to compare against.
    epoch: u64,
    /// Bumped by [`Self::begin`] before a batch's invalidations run. The cache
    /// tier stamps every load with it; this is what lets a load notice it was
    /// overtaken.
    begun: AtomicU64,
    /// Whether the watcher is running and has not reported losing events.
    /// Until it is, the feed answers nothing, because an empty batch would
    /// promise a client that nothing changed.
    live: AtomicBool,
    history: std::sync::Mutex<History>,
    /// The newest published generation; pollers wait on it.
    published: tokio::sync::watch::Sender<u64>,
    retained: usize,
    hold: std::time::Duration,
}

/// What a poll is answered with.
pub struct Batch {
    pub generation: u64,
    pub reset: bool,
    pub modified: Vec<Box<str>>,
    pub created: Vec<Box<str>>,
    pub removed: Vec<Box<str>>,
}

impl Feed {
    pub fn new(retained: usize, hold: std::time::Duration) -> Self {
        let (published, _) = tokio::sync::watch::channel(0);

        Self {
            epoch: fresh_epoch(),
            begun: AtomicU64::new(0),
            live: AtomicBool::new(false),
            history: std::sync::Mutex::new(History {
                changes: VecDeque::new(),
                floor: 0,
            }),
            published,
            retained,
            hold,
        }
    }

    #[inline]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    #[inline]
    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }

    /// The watcher is running: from here on, every change it reports is
    /// published.
    pub fn go_live(&self) {
        self.live.store(true, Ordering::Release);
    }

    /// The watcher failed or lost track of events, so the feed can no longer
    /// vouch for anything. Pollers are woken with a reset and every later poll
    /// is refused, which sends clients back to expiring on a timer.
    pub fn fail(&self) {
        self.live.store(false, Ordering::Release);
        let generation = self.begin();
        self.publish_reset(generation);
    }

    /// Open a generation. Called before the batch's invalidations run, so that
    /// a load started before this point is seen to have been overtaken.
    pub fn begin(&self) -> u64 {
        self.begun.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// The generation a load starting now is stamped with.
    #[inline]
    pub fn current(&self) -> u64 {
        self.begun.load(Ordering::SeqCst)
    }

    /// Whether nothing has begun since `generation`.
    ///
    /// A read-modify-write rather than a load, deliberately. The caller has
    /// just inserted an entry stamped `generation` and is about to vouch for
    /// it; the argument that a later bump's invalidation will see that insert
    /// needs this read ordered before the bump in the counter's modification
    /// order, so that the bump reads from it and synchronises with it. Two
    /// plain atomic accesses on different sides of a `SeqCst` load give no
    /// such happens-before edge; a read-modify-write on the same counter does.
    #[inline]
    pub fn unchanged_since(&self, generation: u64) -> bool {
        self.begun.fetch_add(0, Ordering::SeqCst) == generation
    }

    /// Record what a generation changed, then wake whoever is waiting on it.
    pub fn publish(&self, generation: u64, changes: Vec<(Box<str>, Kind)>) {
        let mut history = self.lock();

        for (path, kind) in changes {
            history.changes.push_back(Change {
                generation,
                kind,
                path,
            });
        }

        while history.changes.len() > self.retained {
            if let Some(evicted) = history.changes.pop_front() {
                history.floor = history.floor.max(evicted.generation);
            }
        }

        drop(history);
        self.published.send_replace(generation);
    }

    /// Publish a generation that tells every client to start over.
    pub fn publish_reset(&self, generation: u64) {
        let mut history = self.lock();
        history.changes.clear();
        history.floor = generation;
        drop(history);

        self.published.send_replace(generation);
    }

    /// Answer a poll from a client at `(epoch, since)`, holding it while there
    /// is nothing newer to say. `None` when the feed is not live.
    pub async fn poll(&self, epoch: u64, since: u64) -> Option<Batch> {
        if !self.is_live() {
            return None;
        }

        let mut published = self.published.subscribe();

        if epoch == self.epoch && since == *published.borrow_and_update() {
            // A timeout is the heartbeat, not an error: answer with an empty
            // batch at the same generation either way.
            let _ = tokio::time::timeout(self.hold, published.changed()).await;
        }

        if !self.is_live() {
            return None;
        }

        Some(self.collect(epoch, since))
    }

    fn collect(&self, epoch: u64, since: u64) -> Batch {
        let generation = *self.published.borrow();
        let history = self.lock();

        if epoch != self.epoch || since > generation || since < history.floor {
            drop(history);
            return Batch::reset(generation);
        }

        // Newest first, so each path keeps the last thing that happened to it.
        // A change of existence outranks a modification seen after it: a
        // client that missed the create still has to hear that the path now
        // exists. Changes are appended in generation order, so the walk stops
        // at the first one the client already has.
        let mut newest: HashMap<&str, Kind> = HashMap::new();

        for change in history.changes.iter().rev() {
            if change.generation <= since {
                break;
            }

            if change.generation > generation {
                continue;
            }

            newest.entry(&change.path)
                .and_modify(|kind| {
                    if *kind == Kind::Modified {
                        *kind = change.kind;
                    }
                })
                .or_insert(change.kind);
        }

        let mut batch = Batch::empty(generation);

        for (path, kind) in newest {
            let list = match kind {
                Kind::Modified => &mut batch.modified,
                Kind::Created => &mut batch.created,
                Kind::Removed => &mut batch.removed,
            };

            list.push(path.into());
        }

        drop(history);
        batch
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, History> {
        // A panic while holding this lock leaves the history at worst short of
        // a batch, and every client would then miss it silently. Refusing to
        // serve from it would be safer still, but a poisoned lock here means a
        // panic in code that only pushes and pops, so recover the guard.
        self.history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Batch {
    const fn empty(generation: u64) -> Self {
        Self {
            generation,
            reset: false,
            modified: Vec::new(),
            created: Vec::new(),
            removed: Vec::new(),
        }
    }

    const fn reset(generation: u64) -> Self {
        let mut batch = Self::empty(generation);
        batch.reset = true;
        batch
    }

    /// Encode as the `ChangeBatch` the schema defines.
    pub fn encode(&self, epoch: u64) -> Bytes {
        let paths = || self.modified.iter().chain(&self.created).chain(&self.removed);
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(
            128 + paths().map(|path| path.len() + 8).sum::<usize>(),
        );

        let mut strings = |paths: &[Box<str>]| {
            let offsets: Vec<_> = paths.iter().map(|path| builder.create_string(path)).collect();
            offsets
        };

        let modified = strings(&self.modified);
        let created = strings(&self.created);
        let removed = strings(&self.removed);

        let modified = builder.create_vector(&modified);
        let created = builder.create_vector(&created);
        let removed = builder.create_vector(&removed);

        let batch = fb::ChangeBatch::create(
            &mut builder,
            &fb::ChangeBatchArgs {
                epoch,
                generation: self.generation,
                reset: self.reset,
                modified: Some(modified),
                created: Some(created),
                removed: Some(removed),
            },
        );

        builder.finish(batch, None);

        Bytes::copy_from_slice(builder.finished_data())
    }
}

/// An epoch no earlier process is likely to have used: the start time in
/// nanoseconds, mixed with the process id so two servers started in the same
/// instant on different hosts behind one name still differ. Never zero, which
/// a client sends when it has no epoch yet.
fn fresh_epoch() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_nanos()).unwrap_or(u64::MAX)
        });

    (nanos ^ u64::from(std::process::id()).rotate_left(32)) | 1
}
