//! `FlatBuffer` encoding.
//!
//! Every expensive encode happens off the request path. A directory's listing
//! is built once, when the directory is scanned, and then handed out as a
//! refcounted [`Bytes`] - so a cache hit costs an atomic increment instead of
//! rebuilding the whole buffer.

use crate::generated::blorg_meta_flat as fb;
use crate::utils::cache::DirNode;
use crate::utils::meta::RawMeta;
use bytes::Bytes;
use std::sync::Arc;

/// A single entry's table is five scalars plus a vtable; this comfortably
/// covers it without a realloc.
const ENTRY_CAPACITY: usize = 96;

/// Table, vtable slot, offset and padding for one child in a listing.
const LISTING_BYTES_PER_CHILD: usize = 64;

/// Root table, both vectors and the file header.
const LISTING_HEADER: usize = 128;

/// One `Descendant` table, its vtable and its slot in the vector.
const DESCENDANT_BYTES: usize = 48;

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

    let directory = directory(
        &mut builder,
        children.iter().map(|(name, meta)| (&**name, *meta)),
        None,
    );

    builder.finish(directory, None);

    Bytes::copy_from_slice(builder.finished_data())
}

/// Encode a directory listing with the listings beneath it.
///
/// `descendants` holds `(parent, subdirectory, node)` in the order the
/// schema's `Descendant` documents. Each listing is encoded again rather than
/// copied out of its node, since a table cannot be spliced in from another
/// buffer.
pub fn subtree(root: &DirNode, descendants: &[(u32, u32, Arc<DirNode>)]) -> Bytes {
    let capacity = descendants
        .iter()
        .map(|(_, _, node)| node.listing().len() + DESCENDANT_BYTES)
        .sum::<usize>()
        + root.listing().len();

    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(capacity);
    let mut encoded = Vec::with_capacity(descendants.len());

    for (parent, subdirectory, node) in descendants {
        let listing = directory(&mut builder, node.children(), None);

        encoded.push(fb::Descendant::create(
            &mut builder,
            &fb::DescendantArgs {
                parent: *parent,
                subdirectory: *subdirectory,
                listing: Some(listing),
            },
        ));
    }

    let descendants_vector = builder.create_vector(&encoded);
    let directory = directory(&mut builder, root.children(), Some(descendants_vector));

    builder.finish(directory, None);

    Bytes::copy_from_slice(builder.finished_data())
}

type Descendants<'fbb> = flatbuffers::WIPOffset<
    flatbuffers::Vector<'fbb, flatbuffers::ForwardsUOffset<fb::Descendant<'fbb>>>,
>;

fn directory<'fbb, 'name>(
    builder: &mut flatbuffers::FlatBufferBuilder<'fbb>,
    children: impl Iterator<Item = (&'name str, RawMeta)>,
    descendants: Option<Descendants<'fbb>>,
) -> flatbuffers::WIPOffset<fb::Directory<'fbb>> {
    let mut subdirectories = Vec::with_capacity(children.size_hint().0);
    let mut files = Vec::with_capacity(children.size_hint().0);

    // A string cannot be created while a table is open, so each child is
    // encoded as one create_string/create pair before the next begins.
    for (name, meta) in children {
        let name_offset = builder.create_string(name);
        if meta.is_dir {
            subdirectories.push(fb::SubdirectoryMetadata::create(
                builder,
                &fb::SubdirectoryMetadataArgs {
                    name: Some(name_offset),
                    created: meta.created,
                    modified: meta.modified,
                    accessed: meta.accessed,
                },
            ));
        } else {
            files.push(fb::FileEntryMetadata::create(
                builder,
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

    fb::Directory::create(
        builder,
        &fb::DirectoryArgs {
            subdirectories: Some(subdirectories_vector),
            files: Some(files_vector),
            descendants,
        },
    )
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
