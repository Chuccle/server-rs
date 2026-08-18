//! Request-path handling.
//!
//! Normalisation is purely lexical: no syscalls, and no heap traffic at all
//! when the request is already in canonical form (the overwhelmingly common
//! case). The resulting key is what the resolution cache is keyed on, which is
//! what lets a warm request reach its payload without ever calling
//! `canonicalize`.

use crate::error::AppError;
use std::borrow::Cow;
use std::path::{Path, PathBuf};

/// Upper bound on path segments. Bounds the on-stack segment table and stops a
/// pathological request from making the normaliser do unbounded work.
const MAX_SEGMENTS: usize = 96;

/// Upper bound on the raw request path.
const MAX_LEN: usize = 4096;

/// Reduce a request path to its canonical relative form.
///
/// Separators are unified to `/`, `.` and empty segments are dropped, and `..`
/// pops a segment - underflowing past the root is a traversal attempt. The
/// empty string denotes the served root itself.
///
/// # Errors
///
/// [`AppError::PathTraversal`] if the path escapes the root, is absurdly long
/// or deep, or contains a segment that the OS would resolve outside the tree.
pub fn normalize(raw: &str) -> Result<Cow<'_, str>, AppError> {
    if raw.len() > MAX_LEN {
        return Err(AppError::PathTraversal);
    }

    let bytes = raw.as_bytes();
    let mut segments = [(0usize, 0usize); MAX_SEGMENTS];
    let mut depth = 0usize;

    // Stays false only while `raw` is byte-for-byte its own normal form, in
    // which case the key can borrow straight out of the query string.
    let mut rewrite = false;

    let mut start = 0usize;
    for index in 0..=bytes.len() {
        // Both separators split segments; only `/` survives into the key.
        // Splitting on ASCII bytes can never land mid-codepoint, so the slices
        // below are always on char boundaries.
        let separator = match bytes.get(index) {
            None | Some(b'/') => true,
            Some(b'\\') => {
                rewrite = true;
                true
            }
            Some(_) => false,
        };

        if !separator {
            continue;
        }

        match &raw[start..index] {
            "" | "." => rewrite = true,
            ".." => {
                rewrite = true;
                depth = depth.checked_sub(1).ok_or(AppError::PathTraversal)?;
            }
            segment => {
                check_segment(segment)?;

                if depth == MAX_SEGMENTS {
                    return Err(AppError::PathTraversal);
                }

                segments[depth] = (start, index);
                depth += 1;
            }
        }

        start = index + 1;
    }

    if !rewrite {
        return Ok(Cow::Borrowed(raw));
    }

    let mut normalized = String::with_capacity(raw.len());
    for &(from, to) in &segments[..depth] {
        if !normalized.is_empty() {
            normalized.push('/');
        }
        normalized.push_str(&raw[from..to]);
    }

    Ok(Cow::Owned(normalized))
}

fn check_segment(segment: &str) -> Result<(), AppError> {
    if segment.as_bytes().contains(&0) {
        return Err(AppError::PathTraversal);
    }

    // On Windows a segment holding ':' is a drive qualifier or an alternate
    // data stream, and `Path::join` honours it by discarding the base entirely.
    // On unix ':' is an ordinary filename byte, so this stays platform-gated.
    #[cfg(windows)]
    {
        if segment.as_bytes().contains(&b':') {
            return Err(AppError::PathTraversal);
        }
    }

    Ok(())
}

/// Turn a normalised key into an absolute path proven to live under `base`.
///
/// `canonicalize` is the only thing that sees through symlinks, junctions,
/// hardlinks and 8.3 aliases, so it remains the authority on containment. The
/// point of the resolution cache is that this runs once per distinct request
/// key rather than once per request.
///
/// `base` must already be canonical; [`crate::utils::cache::Store::new`]
/// guarantees it.
///
/// # Errors
///
/// [`AppError::PathTraversal`] if the resolved path leaves `base`, plus the
/// usual I/O mappings if it cannot be resolved at all.
pub fn resolve_blocking(base: &Path, key: &str) -> Result<PathBuf, AppError> {
    let target = if key.is_empty() {
        base.to_path_buf()
    } else {
        base.join(key)
    };

    let canonical = std::fs::canonicalize(target)?;

    if canonical.starts_with(base) {
        Ok(canonical)
    } else {
        Err(AppError::PathTraversal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(raw: &str) -> String {
        normalize(raw).expect("should normalise").into_owned()
    }

    fn rejected(raw: &str) -> bool {
        matches!(normalize(raw), Err(AppError::PathTraversal))
    }

    #[test]
    fn already_canonical_paths_are_borrowed() {
        // The point of the fast path: no allocation for the common request.
        assert!(matches!(normalize("a/b/c.txt"), Ok(Cow::Borrowed(_))));
        assert!(matches!(normalize("file.txt"), Ok(Cow::Borrowed(_))));
    }

    #[test]
    fn separators_and_noise_are_folded() {
        assert_eq!(key("a\\b\\c.txt"), "a/b/c.txt");
        assert_eq!(key("/a//b/"), "a/b");
        assert_eq!(key("./a/./b"), "a/b");
        assert_eq!(key("a/b/../c"), "a/c");
    }

    #[test]
    fn the_root_normalises_to_the_empty_key() {
        assert_eq!(key(""), "");
        assert_eq!(key("."), "");
        assert_eq!(key("/"), "");
        assert_eq!(key("a/.."), "");
        assert_eq!(key("a/../"), "");
    }

    #[test]
    fn dotdot_may_not_escape_the_root() {
        assert!(rejected(".."));
        assert!(rejected("../passwd"));
        assert!(rejected("/../passwd"));
        assert!(rejected("a/../../passwd"));
        assert!(rejected("..\\passwd"));
        assert!(rejected("a\\..\\..\\passwd"));
        assert!(rejected("a/./../../passwd"));
    }

    #[test]
    fn absurd_inputs_are_rejected_rather_than_worked_on() {
        assert!(rejected(&"a/".repeat(MAX_SEGMENTS + 1)));
        assert!(rejected(&"a".repeat(MAX_LEN + 1)));
        assert!(rejected("a\0b"));
    }

    #[test]
    #[cfg(windows)]
    fn drive_and_stream_qualifiers_are_rejected() {
        // `Path::join` honours these and would discard the base entirely.
        assert!(rejected("C:/Windows/win.ini"));
        assert!(rejected("C:\\Windows\\win.ini"));
        assert!(rejected("file.txt:hidden"));
    }

    #[test]
    fn multibyte_names_survive_normalisation() {
        assert_eq!(key("/файл.txt"), "файл.txt");
        assert_eq!(key("a/😀.md"), "a/😀.md");
    }
}
