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
/// covers it without a realloc. A stored descriptor grows it once.
const ENTRY_CAPACITY: usize = 96;

/// Table, vtable slot, offset and padding for one child in a listing.
const LISTING_BYTES_PER_CHILD: usize = 64;

/// Root table, its vectors and the file header.
const LISTING_HEADER: usize = 128;

/// One `Descendant` table, its vtable and its slot in the vector.
const DESCENDANT_BYTES: usize = 48;

thread_local! {
    /// One builder per worker thread, reused for the life of the process.
    ///
    /// `DirectoryEntryMetadata` is five scalars, so this buffer is allocated
    /// once on first use and only grows for an entry that carries a stored
    /// descriptor - which takes a malloc out of every single-entry request.
    static ENTRY_BUILDER: std::cell::RefCell<flatbuffers::FlatBufferBuilder<'static>> =
        std::cell::RefCell::new(flatbuffers::FlatBufferBuilder::with_capacity(ENTRY_CAPACITY));
}

/// Encode a standalone `DirectoryEntryMetadata`.
///
/// Cheap enough - a pooled builder plus one exactly-sized output allocation -
/// that caching the result per child would cost more memory than it saves time.
/// The output has to be its own allocation regardless: slices of a shared blob
/// would not be eight-byte aligned, which a `FlatBuffer` reader requires.
///
/// `security` is the entry's own descriptor, if it has one stored, and
/// `inherited` what it inherits otherwise, with how many levels up that is.
pub fn entry(meta: &RawMeta, security: Option<&[u8]>, inherited: Option<(&[u8], u32)>) -> Bytes {
    ENTRY_BUILDER.with_borrow_mut(|builder| {
        builder.reset();

        let security = security.map(|descriptor| builder.create_vector(descriptor));
        let (inherited, inherited_depth) = inherited
            .map(|(descriptor, depth)| (Some(builder.create_vector(descriptor)), depth))
            .unwrap_or_default();
        let table = fb::DirectoryEntryMetadata::create(
            builder,
            &fb::DirectoryEntryMetadataArgs {
                size: meta.size,
                created: meta.created,
                modified: meta.modified,
                accessed: meta.accessed,
                directory: meta.is_dir,
                security,
                inherited,
                inherited_depth,
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
/// walked the directory in. `securities` are the descriptors the children's
/// `security` indexes name, and `inherited` what the directory resolves to.
pub fn listing(
    children: &[(Box<str>, RawMeta)],
    securities: &[Bytes],
    inherited: Option<(&[u8], u32)>,
) -> Bytes {
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(estimate(children, securities));

    let directory = directory(
        &mut builder,
        children.iter().map(|(name, meta)| (&**name, *meta)),
        securities,
        inherited,
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
        let listing = directory(
            &mut builder,
            node.children(),
            node.securities(),
            node.inherited(),
            None,
        );

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
    let directory = directory(
        &mut builder,
        root.children(),
        root.securities(),
        root.inherited(),
        Some(descendants_vector),
    );

    builder.finish(directory, None);

    Bytes::copy_from_slice(builder.finished_data())
}

type Descendants<'fbb> = flatbuffers::WIPOffset<
    flatbuffers::Vector<'fbb, flatbuffers::ForwardsUOffset<fb::Descendant<'fbb>>>,
>;

fn directory<'fbb, 'name>(
    builder: &mut flatbuffers::FlatBufferBuilder<'fbb>,
    children: impl Iterator<Item = (&'name str, RawMeta)>,
    securities: &[Bytes],
    inherited: Option<(&[u8], u32)>,
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
                    security: meta.security,
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
                    security: meta.security,
                },
            ));
        }
    }

    let subdirectories_vector = builder.create_vector(&subdirectories);
    let files_vector = builder.create_vector(&files);

    // Left out entirely when nothing in or above the directory has a
    // descriptor, so a tree without any encodes exactly as it did before
    // they existed.
    let security = (!securities.is_empty()).then(|| {
        let tables = securities
            .iter()
            .map(|descriptor| {
                let descriptor = builder.create_vector(descriptor);
                fb::Security::create(
                    builder,
                    &fb::SecurityArgs {
                        descriptor: Some(descriptor),
                    },
                )
            })
            .collect::<Vec<_>>();

        builder.create_vector(&tables)
    });

    let (inherited, inherited_depth) = inherited
        .map(|(descriptor, depth)| (Some(builder.create_vector(descriptor)), depth))
        .unwrap_or_default();

    fb::Directory::create(
        builder,
        &fb::DirectoryArgs {
            subdirectories: Some(subdirectories_vector),
            files: Some(files_vector),
            descendants,
            security,
            inherited,
            inherited_depth,
        },
    )
}

/// Size the builder from the actual names rather than from `MAX_PATH`.
///
/// The previous estimate reserved 324 bytes per child regardless of name
/// length, which meant a 10k-entry directory asked for a 3 MB buffer.
fn estimate(children: &[(Box<str>, RawMeta)], securities: &[Bytes]) -> usize {
    children
        .iter()
        .map(|(name, _)| name.len() + LISTING_BYTES_PER_CHILD)
        .chain(
            securities
                .iter()
                .map(|descriptor| descriptor.len() + LISTING_BYTES_PER_CHILD),
        )
        .sum::<usize>()
        + LISTING_HEADER
}
