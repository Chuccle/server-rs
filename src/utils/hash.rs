//! Hashing for the cache keys and the per-directory child index.
//!
//! The default `SipHash-1-3` costs roughly a nanosecond per byte. That was
//! noise next to the syscalls the old hot path made; now that those are gone,
//! two hashes of an 80-byte path is a visible slice of what a warm request
//! costs. This walks eight bytes at a time and finishes with a strong
//! avalanche, which is enough quality for a hash table and several times
//! faster.
//!
//! Swap [`RandomState`] for `foldhash::fast::RandomState` if you would rather
//! depend on a vetted crate than carry these forty lines - the interface is
//! the same.

/// Odd 64-bit constant with well-distributed bits, from the `splitmix64`
/// family.
const MIX: u64 = 0x517c_c1b7_2722_0a95;

/// `murmur3`'s 64-bit finaliser. Cheap, and it moves every input bit into
/// every output bit, which is what keeps the cheap accumulation loop honest.
#[inline]
const fn avalanche(mut value: u64) -> u64 {
    value ^= value >> 33;
    value = value.wrapping_mul(0xff51_afd7_ed55_8ccd);
    value ^= value >> 33;
    value = value.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    value ^ (value >> 33)
}

/// Hash a directory child's name for [`crate::utils::cache::DirNode`]'s index.
///
/// Unseeded on purpose: this one only orders entries *within* a directory, and
/// every probe verifies the name it lands on, so a collision costs a short scan
/// rather than a wrong answer. Producing one also requires the ability to
/// create files in the served tree.
#[inline]
pub fn name(name: &str) -> u64 {
    let mut state = MIX;
    let (chunks, remainder) = name.as_bytes().as_chunks::<8>();

    for chunk in chunks {
        state = (state ^ u64::from_le_bytes(*chunk)).wrapping_mul(MIX).rotate_left(31);
    }

    if !remainder.is_empty() {
        let mut word = [0u8; 8];
        word[..remainder.len()].copy_from_slice(remainder);
        state = (state ^ u64::from_le_bytes(word)).wrapping_mul(MIX).rotate_left(31);
    }

    avalanche(state ^ u64::try_from(name.len()).unwrap_or(u64::MAX))
}

pub struct Hasher {
    state: u64,
}

impl std::hash::Hasher for Hasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let (chunks, remainder) = bytes.as_chunks::<8>();

        for chunk in chunks {
            self.absorb(u64::from_le_bytes(*chunk));
        }

        if !remainder.is_empty() {
            let mut word = [0u8; 8];
            word[..remainder.len()].copy_from_slice(remainder);
            self.absorb(u64::from_le_bytes(word));
        }

        // Length folds in so that "ab" and "ab\0" cannot collide through the
        // zero padding above.
        self.absorb(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    }

    #[inline]
    fn finish(&self) -> u64 {
        avalanche(self.state)
    }
}

impl Hasher {
    #[inline]
    const fn absorb(&mut self, word: u64) {
        self.state = (self.state ^ word).wrapping_mul(MIX).rotate_left(31);
    }
}

/// Seeded once per process.
///
/// Cache keys come straight from request paths, so an attacker who knew the
/// hash could hand-pick colliding keys and turn every lookup into a list walk.
/// The seed is what removes that; it is the reason this is not just a bare
/// `BuildHasherDefault`.
#[derive(Clone, Copy)]
pub struct RandomState {
    seed: u64,
}

impl Default for RandomState {
    fn default() -> Self {
        static SEED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

        let seed = *SEED.get_or_init(|| {
            use std::hash::{BuildHasher as _, Hasher as _};

            // `std`'s `RandomState` is seeded from the OS. Borrowing one value
            // out of it beats taking a dependency on a random-number crate.
            let mut source = std::collections::hash_map::RandomState::new().build_hasher();
            source.write_u64(MIX);
            source.finish()
        });

        Self { seed }
    }
}

impl std::hash::BuildHasher for RandomState {
    type Hasher = Hasher;

    #[inline]
    fn build_hasher(&self) -> Hasher {
        Hasher { state: self.seed }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::BuildHasher as _;

    #[test]
    fn distinct_names_hash_apart() {
        let names = [
            "", "a", "b", "ab", "ba", "file.txt", "file.txr", "file.txt ",
            "a_rather_longer_name_that_spans_several_words.tar.gz",
            "a_rather_longer_name_that_spans_several_words.tar.gy",
        ];

        let mut seen = std::collections::HashSet::new();
        for candidate in names {
            assert!(seen.insert(name(candidate)), "collision on {candidate:?}");
        }
    }

    #[test]
    fn zero_padding_does_not_alias() {
        // The tail of a short chunk is zero-filled, so length has to be folded
        // in or these would be the same hash.
        assert_ne!(name("ab"), name("ab\0"));
        assert_ne!(name("abcdefgh"), name("abcdefgh\0"));
    }

    #[test]
    fn build_hasher_agrees_with_itself_and_differs_across_keys() {
        let state = RandomState::default();
        assert_eq!(state.hash_one("some/path"), state.hash_one("some/path"));
        assert_ne!(state.hash_one("some/path"), state.hash_one("some/pat"));
        assert_ne!(state.hash_one("some/path"), state.hash_one("some/path/"));
    }

    #[test]
    fn hashes_spread_across_the_whole_word() {
        // A weak finaliser tends to leave the high or low bits constant, which
        // shows up as buckets never being used.
        let (mut ones, mut zeroes) = (0u64, u64::MAX);
        for index in 0..1024u32 {
            let hash = name(&format!("entry_{index}.txt"));
            ones |= hash;
            zeroes &= hash;
        }
        assert_eq!(ones, u64::MAX, "some bit was never set");
        assert_eq!(zeroes, 0, "some bit was never clear");
    }
}
