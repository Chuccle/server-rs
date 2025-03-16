pub mod metadata {

    #[derive(Debug, Clone, serde::Serialize)]
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
        sub_dir_map: std::collections::HashMap<String, usize>, // Maps sub_dir -> index in files
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
            self.files.created_times.push(
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
                        .modified()
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

        fn create_entry_metadata<'a>(
            &self,
            builder: &mut flatbuffers::FlatBufferBuilder<'a>,
            idx: usize,
        ) -> flatbuffers::WIPOffset<crate::generated::blorg_meta_flat::DirectoryEntryMetadata<'a>>
        {
            let file_name = builder.create_string(&self.files.names[idx]);

            crate::generated::blorg_meta_flat::DirectoryEntryMetadata::create(
                builder,
                &crate::generated::blorg_meta_flat::DirectoryEntryMetadataArgs {
                    name: Some(file_name),
                    size: self.files.sizes[idx],
                    created: self.files.created_times[idx],
                    modified: self.files.modified_times[idx],
                    accessed: self.files.access_times[idx],
                },
            )
        }

        pub fn get_file_serialized(&self, name: &str) -> Option<Vec<u8>> {
            self.file_map.get(name).map(|&index| {
                let capacity = Self::estimate_serialized_size(1);

                let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(capacity as usize);
                let file = self.create_entry_metadata(&mut builder, index);
                builder.finish(file, None);
                builder.finished_data().to_vec()
            })
        }

        fn estimate_serialized_size(count: usize) -> u64 {
            (std::mem::size_of::<DirEntMetaEntries>() as u64
                + crate::utils::windows::file::WINDOWS_MAX_PATH)
                * count as u64
        }
    }
}
