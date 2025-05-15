pub mod metadata {

    #[derive(Debug, Clone)]
    pub struct DirEntMetaEntries {
        names: Vec<String>,
        sizes: Vec<u64>,
        created_times: Vec<u64>,
        modified_times: Vec<u64>,
        access_times: Vec<u64>,
    }
    impl DirEntMetaEntries {
        pub fn new() -> Self {
            Self {
                names: Vec::new(),
                sizes: Vec::new(),
                created_times: Vec::new(),
                modified_times: Vec::new(),
                access_times: Vec::new(),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct DirectoryLookupContext {
        // Contiguous storage for cache efficiency
        files: DirEntMetaEntries,
        sub_dirs: DirEntMetaEntries,
        // Fast lookup
        file_map: std::collections::HashMap<String, usize>, // Maps filename -> index in files
        sub_dir_map: std::collections::HashMap<String, usize>, // Maps sub_dirs -> index in sub_dirs
    }

    impl DirectoryLookupContext {
        pub fn new() -> Self {
            Self {
                files: DirEntMetaEntries::new(),
                sub_dirs: DirEntMetaEntries::new(),
                file_map: std::collections::HashMap::new(),
                sub_dir_map: std::collections::HashMap::new(),
            }
        }

        pub fn add_file(&mut self, metadata: &std::fs::Metadata, name: &str) {
            let idx = self.files.names.len();
            self.file_map.insert(name.to_owned(), idx);
            self.files.names.push(name.to_owned());
            self.files.sizes.push(metadata.len());
            self.files.created_times.push(
                crate::utils::windows::time::IntoFileTime::into_file_time(
                    metadata
                        .created()
                        .unwrap_or_else(|_| std::time::SystemTime::now()),
                ),
            );
            self.files.modified_times.push(
                crate::utils::windows::time::IntoFileTime::into_file_time(
                    metadata
                        .modified()
                        .unwrap_or_else(|_| std::time::SystemTime::now()),
                ),
            );
            self.files.access_times.push(
                crate::utils::windows::time::IntoFileTime::into_file_time(
                    metadata
                        .accessed()
                        .unwrap_or_else(|_| std::time::SystemTime::now()),
                ),
            );
        }

        pub fn add_subdir(&mut self, metadata: &std::fs::Metadata, name: &str) {
            let idx = self.sub_dirs.names.len();
            self.sub_dir_map.insert(name.to_owned(), idx);
            self.sub_dirs.names.push(name.to_owned());
            self.sub_dirs.sizes.push(metadata.len());
            self.sub_dirs.created_times.push(
                crate::utils::windows::time::IntoFileTime::into_file_time(
                    metadata
                        .created()
                        .unwrap_or_else(|_| std::time::SystemTime::now()),
                ),
            );
            self.sub_dirs.modified_times.push(
                crate::utils::windows::time::IntoFileTime::into_file_time(
                    metadata
                        .modified()
                        .unwrap_or_else(|_| std::time::SystemTime::now()),
                ),
            );
            self.sub_dirs.access_times.push(
                crate::utils::windows::time::IntoFileTime::into_file_time(
                    metadata
                        .accessed()
                        .unwrap_or_else(|_| std::time::SystemTime::now()),
                ),
            );
        }

        fn create_entries_metadata<'a>(
            &self,
            builder: &mut flatbuffers::FlatBufferBuilder<'a>,
            entries: &DirEntMetaEntries,
        ) -> flatbuffers::WIPOffset<crate::generated::blorg_meta_flat::DirectoryEntriesMetadata<'a>>
        {
            // First create all string objects
            let names: Vec<flatbuffers::WIPOffset<_>> = entries
                .names
                .iter()
                .map(|name| builder.create_string(name))
                .collect();

            let names_vector = builder.create_vector(&names);
            let sizes_vector = builder.create_vector(&entries.sizes);
            let created_vector = builder.create_vector(&entries.created_times);
            let modified_vector = builder.create_vector(&entries.modified_times);
            let accessed_vector = builder.create_vector(&entries.access_times);

            crate::generated::blorg_meta_flat::DirectoryEntriesMetadata::create(
                builder,
                &crate::generated::blorg_meta_flat::DirectoryEntriesMetadataArgs {
                    name: Some(names_vector),
                    size: Some(sizes_vector),
                    created: Some(created_vector),
                    modified: Some(modified_vector),
                    accessed: Some(accessed_vector),
                },
            )
        }

        pub fn get_all_entries_serialized(&self) -> Vec<u8> {
            let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(
                Self::estimate_serialized_size(self.files.names.len() + self.sub_dirs.names.len())
                    as usize,
            );

            let directories = self.create_entries_metadata(&mut builder, &self.sub_dirs);

            let files = self.create_entries_metadata(&mut builder, &self.files);

            let directory = crate::generated::blorg_meta_flat::Directory::create(
                &mut builder,
                &crate::generated::blorg_meta_flat::DirectoryArgs {
                    directory_count: self.sub_dirs.names.len() as u64,
                    file_count: self.files.names.len() as u64,
                    directories: Some(directories),
                    files: Some(files),
                },
            );

            builder.finish(directory, None);
            builder.finished_data().to_owned()
        }

        #[inline]
        fn create_dir_entry_flatbuffer<'a>(
            builder: &mut flatbuffers::FlatBufferBuilder<'a>,
            idx: usize,
            source_entries: &DirEntMetaEntries,
            is_directory_entry: bool,
        ) -> flatbuffers::WIPOffset<crate::generated::blorg_meta_flat::DirectoryEntryMetadata<'a>>
        {
            let args = crate::generated::blorg_meta_flat::DirectoryEntryMetadataArgs {
                size: source_entries.sizes[idx],
                created: source_entries.created_times[idx],
                modified: source_entries.modified_times[idx],
                accessed: source_entries.access_times[idx],
                directory: is_directory_entry,
            };
            crate::generated::blorg_meta_flat::DirectoryEntryMetadata::create(builder, &args)
        }

        #[inline]
        pub fn get_dir_entry_serialized(&self, name: &str, is_directory: bool) -> Option<Vec<u8>> {
            let (source, index_option) = if is_directory {
                (&self.sub_dirs, self.sub_dir_map.get(name).copied())
            } else {
                (&self.files, self.file_map.get(name).copied())
            };

            index_option.map(|index| {
                let capacity = Self::estimate_serialized_size(1);
                let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(capacity as usize);
                let dir_entry =
                    Self::create_dir_entry_flatbuffer(&mut builder, index, source, is_directory);
                builder.finish(dir_entry, None);
                builder.finished_data().to_vec()
            })
        }

        #[inline]
        fn estimate_serialized_size(count: usize) -> u64 {
            (std::mem::size_of::<DirEntMetaEntries>() as u64
                + crate::utils::windows::file::WINDOWS_MAX_PATH)
                * count as u64
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
