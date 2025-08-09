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
        fn new(metadata: &std::fs::Metadata) -> Self {
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

        #[inline]
        fn to_meta_times(self) -> crate::generated::blorg_meta_flat::MetaTimes {
            crate::generated::blorg_meta_flat::MetaTimes::new(
                self.created,
                self.modified,
                self.accessed,
            )
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub struct SubdirectoryEntry {
        created: u64,
        modified: u64,
        accessed: u64,
    }

    impl SubdirectoryEntry {
        #[inline]
        fn new(metadata: &std::fs::Metadata) -> Self {
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

        #[inline]
        fn to_meta_times(self) -> crate::generated::blorg_meta_flat::MetaTimes {
            crate::generated::blorg_meta_flat::MetaTimes::new(
                self.created,
                self.modified,
                self.accessed,
            )
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub enum EntryType {
        File(FileEntry),
        Directory(SubdirectoryEntry),
    }

    #[derive(Debug, Clone)]
    pub struct DirectoryLookupContext {
        files: Vec<FileEntry>,
        file_names: Vec<String>,
        sub_dirs: Vec<SubdirectoryEntry>,
        sub_dir_names: Vec<String>,
        name_to_entry: std::collections::HashMap<String, (bool, usize)>,
    }

    impl DirectoryLookupContext {
        pub fn new() -> Self {
            Self {
                files: Vec::new(),
                file_names: Vec::new(),
                sub_dirs: Vec::new(),
                sub_dir_names: Vec::new(),
                name_to_entry: std::collections::HashMap::new(),
            }
        }

        #[inline]
        pub fn add_file(&mut self, metadata: &std::fs::Metadata, name: &str) {
            let idx = self.files.len();
            let entry = FileEntry::new(metadata);

            self.files.push(entry);
            self.file_names.push(name.to_owned());
            self.name_to_entry.insert(name.to_owned(), (false, idx));
        }

        #[inline]
        pub fn add_subdir(&mut self, metadata: &std::fs::Metadata, name: &str) {
            let idx = self.sub_dirs.len();
            let entry = SubdirectoryEntry::new(metadata);

            self.sub_dirs.push(entry);
            self.sub_dir_names.push(name.to_owned());
            self.name_to_entry.insert(name.to_owned(), (true, idx));
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
                self.name_to_entry.reserve(lower);
            }

            for (metadata, name, is_directory) in entries_iter {
                if is_directory {
                    self.add_subdir(&metadata, &name);
                } else {
                    self.add_file(&metadata, &name);
                }
            }
        }

        #[inline]
        pub fn get_entry(&self, name: &str) -> Option<(&str, EntryType)> {
            let &(is_dir, idx) = self.name_to_entry.get(name)?;

            if is_dir {
                let entry = self.sub_dirs.get(idx)?;
                let name = self.sub_dir_names.get(idx)?;
                Some((name, EntryType::Directory(*entry)))
            } else {
                let entry = self.files.get(idx)?;
                let name = self.file_names.get(idx)?;
                Some((name, EntryType::File(*entry)))
            }
        }

        pub fn get_all_entries_serialized(&self) -> Vec<u8> {
            let file_count = self.files.len();
            let dir_count = self.sub_dirs.len();
            let capacity = Self::estimate_serialized_size(file_count + dir_count) as usize;

            let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(capacity);

            let dir_metadata: Vec<_> = self
                .sub_dirs
                .iter()
                .zip(self.sub_dir_names.iter())
                .map(|(entry, name)| {
                    let times = entry.to_meta_times();
                    let name_fb = builder.create_string(name);
                    crate::generated::blorg_meta_flat::SubdirectoryMetadata::create(
                        &mut builder,
                        &crate::generated::blorg_meta_flat::SubdirectoryMetadataArgs {
                            name: Some(name_fb),
                            times: Some(&times),
                        },
                    )
                })
                .collect();

            let file_metadata: Vec<_> = self
                .files
                .iter()
                .zip(self.file_names.iter())
                .map(|(entry, name)| {
                    let times = entry.to_meta_times();
                    let name_fb = builder.create_string(name);
                    crate::generated::blorg_meta_flat::FileEntryMetadata::create(
                        &mut builder,
                        &crate::generated::blorg_meta_flat::FileEntryMetadataArgs {
                            name: Some(name_fb),
                            size: entry.size,
                            times: Some(&times),
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
        pub fn get_dir_entry_serialized(&self, name: &str) -> Option<Vec<u8>> {
            let (_name, entry) = self.get_entry(name)?;

            let capacity = Self::estimate_single_entry_size();
            let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(capacity);

            let (size, created, modified, accessed, is_directory) = match entry {
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
            Some(builder.finished_data().to_vec())
        }

        #[inline]
        fn estimate_serialized_size(count: usize) -> u64 {
            const FLATBUFFER_OVERHEAD: u64 = 128;
            const METADATA_SIZE: u64 = 64;

            (METADATA_SIZE + crate::utils::windows::file::WINDOWS_MAX_PATH) * count as u64
                + FLATBUFFER_OVERHEAD
        }

        #[inline]
        fn estimate_single_entry_size() -> usize {
            128
        }
    }

    pub async fn handle_fs_events(
        events: &Vec<notify_debouncer_full::DebouncedEvent>,
        meta_cache: &scc::HashCache<
            std::path::PathBuf,
            (std::sync::Arc<DirectoryLookupContext>, tokio::time::Instant),
        >,
    ) {
        for event in events {
            match event.kind {
                notify_debouncer_full::notify::EventKind::Create(_) => {
                    debug_assert_eq!(event.paths.len(), 1);

                    crate::log_trace!("file watch event info: {:?}", event);

                    let Some(path) = event.paths.first() else {
                        continue;
                    };

                    if let Some(parent_path) = path.parent() {
                        // Remove parent's cache entry as it will now be dirty if it exists
                        _ = meta_cache
                            .remove_if_async(parent_path, |entry| event.time > entry.1.into())
                            .await;
                    };
                }
                notify_debouncer_full::notify::EventKind::Remove(remove_kind) => {
                    debug_assert_eq!(event.paths.len(), 1);

                    crate::log_trace!("file watch event info: {:?}", event);

                    let Some(path) = event.paths.first() else {
                        continue;
                    };

                    if let Some(parent_path) = path.parent() {
                        _ = meta_cache
                            .remove_if_async(parent_path, |entry| event.time > entry.1.into())
                            .await;
                    }

                    match remove_kind {
                        notify_debouncer_full::notify::event::RemoveKind::File => {
                            _ = meta_cache
                                .remove_if_async(path, |entry| event.time > entry.1.into())
                                .await;
                        }
                        notify_debouncer_full::notify::event::RemoveKind::Folder => {
                            meta_cache
                                .retain_async(|key, value| {
                                    // Keep if the key is outside the path
                                    if !key.starts_with(path) {
                                        return true;
                                    }

                                    // Keep if the entry timestamp is newer than the event's
                                    if event.time <= value.1.into() {
                                        return true;
                                    }

                                    // Otherwise, remove it
                                    false
                                })
                                .await;
                        }
                        _ => {}
                    }
                }
                notify_debouncer_full::notify::EventKind::Modify(_) => {
                    crate::log_trace!("file watch event info: {:?}", event);

                    let Some(path) = event.paths.first() else {
                        continue;
                    };

                    if let Some(parent_path) = path.parent() {
                        _ = meta_cache
                            .remove_if_async(parent_path, |entry| event.time > entry.1.into())
                            .await;
                    }

                    // this is ugly but since we have no file/directory context it'll have to do
                    meta_cache
                        .retain_async(|key, value| {
                            // Keep if the key is outside the path
                            if !key.starts_with(path) {
                                return true;
                            }

                            // Keep if the entry timestamp is newer than the event's
                            if event.time <= value.1.into() {
                                return true;
                            }

                            // Otherwise, remove it
                            false
                        })
                        .await;
                }
                notify_debouncer_full::notify::EventKind::Other => {
                    crate::log_trace!("file watch event info: {:?}", event);
                    if event.need_rescan() {
                        crate::log_warn!("file watch rescan flag received, cache invalidated");
                        meta_cache.clear_async().await;
                        return;
                    }
                }
                _ => {
                    crate::log_trace!("file watch event info: {:?}", event);
                }
            }
        }
    }
}
