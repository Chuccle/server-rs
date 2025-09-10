pub mod metadata {

    #[derive(Debug, Clone, Copy)]
    pub struct FileEntry {
        size: u64,
        created: u64,
        modified: u64,
        accessed: u64,
    }

    impl FileEntry {
        #[inline]
        pub fn new(metadata: &std::fs::Metadata) -> Self {
            Self {
                size: metadata.len(),
                created: crate::utils::windows::time::IntoFileTime::into_file_time(
                    metadata
                        .created()
                        .unwrap_or_else(|_| std::time::SystemTime::now()),
                ),
                modified: crate::utils::windows::time::IntoFileTime::into_file_time(
                    metadata
                        .modified()
                        .unwrap_or_else(|_| std::time::SystemTime::now()),
                ),
                accessed: crate::utils::windows::time::IntoFileTime::into_file_time(
                    metadata
                        .accessed()
                        .unwrap_or_else(|_| std::time::SystemTime::now()),
                ),
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub struct DirectoryEntry {
        created: u64,
        modified: u64,
        accessed: u64,
    }

    impl DirectoryEntry {
        #[inline]
        pub fn new(metadata: &std::fs::Metadata) -> Self {
            Self {
                created: crate::utils::windows::time::IntoFileTime::into_file_time(
                    metadata
                        .created()
                        .unwrap_or_else(|_| std::time::SystemTime::now()),
                ),
                modified: crate::utils::windows::time::IntoFileTime::into_file_time(
                    metadata
                        .modified()
                        .unwrap_or_else(|_| std::time::SystemTime::now()),
                ),
                accessed: crate::utils::windows::time::IntoFileTime::into_file_time(
                    metadata
                        .accessed()
                        .unwrap_or_else(|_| std::time::SystemTime::now()),
                ),
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub enum EntryType {
        File(FileEntry),
        Directory(DirectoryEntry),
    }

    impl EntryType {
        #[inline]
        pub fn get_dir_entry_serialized(&self) -> Vec<u8> {
            let capacity = 64;
            let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(capacity);

            let (size, created, modified, accessed, is_directory) = match self {
                EntryType::File(f) => (f.size, f.created, f.modified, f.accessed, false),
                EntryType::Directory(d) => (0, d.created, d.modified, d.accessed, true),
            };

            let dir_entry = crate::generated::blorg_meta_flat::DirectoryEntryMetadata::create(
                &mut builder,
                &crate::generated::blorg_meta_flat::DirectoryEntryMetadataArgs {
                    size,
                    created,
                    modified,
                    accessed,
                    directory: is_directory,
                },
            );

            builder.finish(dir_entry, None);
            builder.finished_data().to_vec()
        }
    }

    #[derive(Debug, Clone)]
    pub struct DirectoryLookupContext {
        files: Vec<FileEntry>,
        file_names: Vec<String>,
        sub_dirs: Vec<DirectoryEntry>,
        sub_dir_names: Vec<String>,
    }

    impl DirectoryLookupContext {
        pub fn new() -> Self {
            Self {
                files: Vec::new(),
                file_names: Vec::new(),
                sub_dirs: Vec::new(),
                sub_dir_names: Vec::new(),
            }
        }

        #[inline]
        pub fn add_file(&mut self, metadata: &std::fs::Metadata, name: &str) {
            let entry = FileEntry::new(metadata);

            self.files.push(entry);
            self.file_names.push(name.to_owned());
        }

        #[inline]
        pub fn add_subdir(&mut self, metadata: &std::fs::Metadata, name: &str) {
            let entry = DirectoryEntry::new(metadata);

            self.sub_dirs.push(entry);
            self.sub_dir_names.push(name.to_owned());
        }

        pub fn add_entries_batch<I>(&mut self, entries: I)
        where
            I: IntoIterator<Item = (std::fs::Metadata, String, bool)>,
        {
            let entries_iter = entries.into_iter();

            // Pre-allocate if we have size hints
            if let (lower, Some(_upper)) = entries_iter.size_hint() {
                let estimated_files = lower / 2; // rough estimate
                let estimated_dirs = lower - estimated_files;

                self.files.reserve(estimated_files);
                self.file_names.reserve(estimated_files);
                self.sub_dirs.reserve(estimated_dirs);
                self.sub_dir_names.reserve(estimated_dirs);
            }

            for (metadata, name, is_directory) in entries_iter {
                if is_directory {
                    self.add_subdir(&metadata, &name);
                } else {
                    self.add_file(&metadata, &name);
                }
            }
        }

        pub fn get_all_entries_serialized(&self) -> Vec<u8> {
            let file_count = self.files.len();
            let dir_count = self.sub_dirs.len();
            let capacity = Self::estimate_serialized_size(file_count + dir_count);

            let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(capacity);

            let dir_metadata: Vec<_> = self
                .sub_dirs
                .iter()
                .zip(self.sub_dir_names.iter())
                .map(|(entry, name)| {
                    let name_fb = builder.create_string(name);
                    crate::generated::blorg_meta_flat::SubdirectoryMetadata::create(
                        &mut builder,
                        &crate::generated::blorg_meta_flat::SubdirectoryMetadataArgs {
                            name: Some(name_fb),
                            accessed: entry.accessed,
                            modified: entry.modified,
                            created: entry.created,
                        },
                    )
                })
                .collect();

            let file_metadata: Vec<_> = self
                .files
                .iter()
                .zip(self.file_names.iter())
                .map(|(entry, name)| {
                    let name_fb = builder.create_string(name);
                    crate::generated::blorg_meta_flat::FileEntryMetadata::create(
                        &mut builder,
                        &crate::generated::blorg_meta_flat::FileEntryMetadataArgs {
                            name: Some(name_fb),
                            size: entry.size,
                            accessed: entry.accessed,
                            modified: entry.modified,
                            created: entry.created,
                        },
                    )
                })
                .collect();

            let directories_vector = builder.create_vector(&dir_metadata);
            let files_vector = builder.create_vector(&file_metadata);

            let directory = crate::generated::blorg_meta_flat::Directory::create(
                &mut builder,
                &crate::generated::blorg_meta_flat::DirectoryArgs {
                    subdirectories: Some(directories_vector),
                    files: Some(files_vector),
                },
            );

            builder.finish(directory, None);
            builder.finished_data().to_vec()
        }

        #[inline]
        fn estimate_serialized_size(count: usize) -> usize {
            const FLATBUFFER_OVERHEAD_SIZE: usize = 128;
            const METADATA_SIZE: usize = 64;

            (METADATA_SIZE + crate::utils::windows::file::WINDOWS_MAX_PATH as usize) * count
                + FLATBUFFER_OVERHEAD_SIZE
        }
    }

    pub async fn handle_fs_events(
        events: &Vec<notify_debouncer_full::DebouncedEvent>,
        directory_cache: &moka::future::Cache<
            std::path::PathBuf,
            std::sync::Arc<DirectoryLookupContext>,
        >,
        file_cache: &moka::future::Cache<std::path::PathBuf, EntryType>,
    ) {
        let mut paths_to_invalidate = std::collections::HashSet::new();
        let mut parents_to_invalidate = std::collections::HashSet::new();
        let mut prefix_patterns = Vec::new();
        let mut needs_full_invalidation = false;

        for event in events {
            crate::log_trace!("Processing file watch event: {:?}", event);

            match event.kind {
                notify_debouncer_full::notify::EventKind::Create(_) => {
                    if let Some(path) = event.paths.first()
                        && let Some(parent_path) = path.parent()
                    {
                        parents_to_invalidate.insert(parent_path.to_path_buf());
                    }
                }

                notify_debouncer_full::notify::EventKind::Remove(remove_kind) => {
                    if let Some(path) = event.paths.first() {
                        // Always invalidate parent directory
                        if let Some(parent_path) = path.parent() {
                            parents_to_invalidate.insert(parent_path.to_path_buf());
                        }

                        match remove_kind {
                            notify_debouncer_full::notify::event::RemoveKind::File => {
                                paths_to_invalidate.insert(path.clone());
                            }
                            notify_debouncer_full::notify::event::RemoveKind::Folder => {
                                // For folder removal, we need prefix-based invalidation
                                prefix_patterns.push(path.clone());
                            }
                            _ => {
                                // Conservative approach for unknown remove types
                                prefix_patterns.push(path.clone());
                            }
                        }
                    }
                }

                notify_debouncer_full::notify::EventKind::Modify(modify_kind) => {
                    if let Some(path) = event.paths.first() {
                        // Always invalidate parent directory
                        if let Some(parent_path) = path.parent() {
                            parents_to_invalidate.insert(parent_path.to_path_buf());
                        }

                        match modify_kind {
                            notify_debouncer_full::notify::event::ModifyKind::Name(_) => {
                                // Rename operations - invalidate both old and new paths if available
                                prefix_patterns.push(path.clone());
                            }
                            notify_debouncer_full::notify::event::ModifyKind::Data(_) => {
                                // File content changes - only invalidate the specific file
                                paths_to_invalidate.insert(path.clone());
                            }
                            notify_debouncer_full::notify::event::ModifyKind::Metadata(_) => {
                                // Metadata changes - invalidate file and potentially parent
                                paths_to_invalidate.insert(path.clone());
                            }
                            _ => {
                                // Conservative fallback
                                prefix_patterns.push(path.clone());
                            }
                        }
                    }
                }

                notify_debouncer_full::notify::EventKind::Other => {
                    if event.need_rescan() {
                        crate::log_warn!(
                            "File watch rescan flag received, full cache invalidation required"
                        );
                        needs_full_invalidation = true;
                        break; // No need to process other events if full invalidation needed
                    }
                }

                _ => {
                    crate::log_trace!("Unhandled event type: {:?}", event.kind);
                }
            }
        }

        // Early return for full invalidation
        if needs_full_invalidation {
            directory_cache.invalidate_all();
            file_cache.invalidate_all();
            return;
        }

        // Batch execute invalidations
        execute_invalidations(
            directory_cache,
            file_cache,
            paths_to_invalidate,
            parents_to_invalidate,
            prefix_patterns,
        )
        .await;
    }

    async fn execute_invalidations(
        directory_cache: &moka::future::Cache<
            std::path::PathBuf,
            std::sync::Arc<DirectoryLookupContext>,
        >,
        file_cache: &moka::future::Cache<std::path::PathBuf, EntryType>,
        direct_paths: std::collections::HashSet<std::path::PathBuf>,
        parent_paths: std::collections::HashSet<std::path::PathBuf>,
        prefix_patterns: Vec<std::path::PathBuf>,
    ) {
        let mut all_paths = direct_paths;
        all_paths.extend(parent_paths);

        for path in &all_paths {
            directory_cache.invalidate(path).await;
            file_cache.invalidate(path).await;
        }

        if !prefix_patterns.is_empty() {
            let prefixes = prefix_patterns.clone();
            let _ = directory_cache.invalidate_entries_if(move |key, _| {
                prefixes.iter().any(|prefix| key.starts_with(prefix))
            });

            let prefixes = prefix_patterns;
            let _ = file_cache.invalidate_entries_if(move |key, _| {
                prefixes.iter().any(|prefix| key.starts_with(prefix))
            });
        }
    }
}
