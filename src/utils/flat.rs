//! `FlatBuffer` encoding.
//!
//! Every expensive encode happens off the request path. A directory's listing
//! is built once, when the directory is scanned, and then handed out as a
//! refcounted [`Bytes`] - so a cache hit costs an atomic increment instead of
//! rebuilding the whole buffer.

use crate::generated::blorg_meta_flat as fb;
use crate::utils::meta::RawMeta;
use bytes::Bytes;

/// A single entry's table is five scalars plus a vtable; this comfortably
/// covers it without a realloc.
const ENTRY_CAPACITY: usize = 96;

/// Table, vtable slot, offset and padding for one child in a listing.
const LISTING_BYTES_PER_CHILD: usize = 64;

/// Root table, both vectors and the file header.
const LISTING_HEADER: usize = 128;

thread_local! {
    /// One builder per worker thread, reused for the life of the process.
    ///
    /// `DirectoryEntryMetadata` is five scalars, so this buffer is allocated
    /// once on first use and never grows again - which takes a malloc out of
    /// every single-entry request.
    static ENTRY_BUILDER: std::cell::RefCell<flatbuffers::FlatBufferBuilder<'static>> =
        std::cell::RefCell::new(flatbuffers::FlatBufferBuilder::with_capacity(ENTRY_CAPACITY));
}

/// Encode a standalone `DirectoryEntryMetadata`.
///
/// Cheap enough - a pooled builder plus one exactly-sized output allocation -
/// that caching the result per child would cost more memory than it saves time.
/// The output has to be its own allocation regardless: slices of a shared blob
/// would not be eight-byte aligned, which a `FlatBuffer` reader requires.
pub fn entry(meta: &RawMeta) -> Bytes {
    ENTRY_BUILDER.with_borrow_mut(|builder| {
        builder.reset();

        let table = fb::DirectoryEntryMetadata::create(
            builder,
            &fb::DirectoryEntryMetadataArgs {
                size: meta.size,
                created: meta.created,
                modified: meta.modified,
                accessed: meta.accessed,
                directory: meta.is_dir,
            },
        );

        builder.finish(table, None);

        Bytes::copy_from_slice(builder.finished_data())
    })
}

/// Encode a whole directory listing.
///
/// `children` is expected to be sorted by name; the two output vectors keep
/// that order, so clients see a stable listing no matter what order the OS
/// walked the directory in.
pub fn listing(children: &[(Box<str>, RawMeta)]) -> Bytes {
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(estimate(children));

    // A string cannot be created while a table is open, so each child is
    // encoded as one create_string/create pair before the next begins.
    let mut subdirectories = Vec::with_capacity(children.len());
    let mut files = Vec::with_capacity(children.len());

    for (name, meta) in children {
        let name_offset = builder.create_string(name);
        if meta.is_dir {
            subdirectories.push(fb::SubdirectoryMetadata::create(
                &mut builder,
                &fb::SubdirectoryMetadataArgs {
                    name: Some(name_offset),
                    created: meta.created,
                    modified: meta.modified,
                    accessed: meta.accessed,
                },
            ));
        } else {
            files.push(fb::FileEntryMetadata::create(
                &mut builder,
                &fb::FileEntryMetadataArgs {
                    name: Some(name_offset),
                    size: meta.size,
                    created: meta.created,
                    modified: meta.modified,
                    accessed: meta.accessed,
                },
            ));
        }
    }

    let subdirectories_vector = builder.create_vector(&subdirectories);
    let files_vector = builder.create_vector(&files);

    let directory = fb::Directory::create(
        &mut builder,
        &fb::DirectoryArgs {
            subdirectories: Some(subdirectories_vector),
            files: Some(files_vector),
        },
    );

    builder.finish(directory, None);

    Bytes::copy_from_slice(builder.finished_data())
}

/// Size the builder from the actual names rather than from `MAX_PATH`.
///
/// The previous estimate reserved 324 bytes per child regardless of name
/// length, which meant a 10k-entry directory asked for a 3 MB buffer.
fn estimate(children: &[(Box<str>, RawMeta)]) -> usize {
    children
        .iter()
        .map(|(name, _)| name.len() + LISTING_BYTES_PER_CHILD)
        .sum::<usize>()
        + LISTING_HEADER
}
