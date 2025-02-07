pub mod metadata {

    #[derive(Debug, Clone)]
    pub struct DirEntMetaEntries {
        names: Vec<String>,
        sizes: Vec<u64>,
        modified_times: Vec<crate::utils::windows::time::File>,
        access_times: Vec<crate::utils::windows::time::File>,
    }
    impl DirEntMetaEntries {
        pub fn new() -> Self {
            Self {
                names: Vec::new(),
                sizes: Vec::new(),
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
            self.files.modified_times.push(
                metadata
                    .modified()
                    .unwrap_or_else(|_| std::time::SystemTime::now())
                    .into(),
            );
            self.files.access_times.push(
                metadata
                    .accessed()
                    .unwrap_or_else(|_| std::time::SystemTime::now())
                    .into(),
            );
        }

        pub fn add_subdir(&mut self, metadata: &std::fs::Metadata, name: &str) {
            let idx = self.sub_dirs.names.len();
            self.sub_dir_map.insert(name.to_owned(), idx);
            self.sub_dirs.names.push(name.to_owned());
            self.sub_dirs.sizes.push(metadata.len());
            self.sub_dirs.modified_times.push(
                metadata
                    .modified()
                    .unwrap_or_else(|_| std::time::SystemTime::now())
                    .into(),
            );
            self.sub_dirs.access_times.push(
                metadata
                    .modified()
                    .unwrap_or_else(|_| std::time::SystemTime::now())
                    .into(),
            );
        }

        pub fn get_all_entries(&self) -> Result<Vec<u8>, crate::AppError> {
            let total_entries = self.files.names.len() + self.sub_dirs.names.len();

            let mut msg = capnp::message::Builder::new_default();
            let mut entries = msg
                .init_root::<crate::generated::metadata_capnp::directory_entries_metadata::Builder>(
            );

            macro_rules! init_and_set {
                ($field:ident, $values:expr) => {
                    let mut field = entries.reborrow().$field(total_entries.try_into()?);
                    for (i, value) in $values.enumerate() {
                        field.set(i.try_into()?, value);
                    }
                };
            }

            init_and_set!(
                init_is_dir,
                self.files
                    .names
                    .iter()
                    .map(|_| false)
                    .chain(self.sub_dirs.names.iter().map(|_| true))
            );
            init_and_set!(
                init_name,
                self.files
                    .names
                    .iter()
                    .chain(&self.sub_dirs.names)
                    .map(ToOwned::to_owned)
            );
            init_and_set!(
                init_size,
                self.files.sizes.iter().chain(&self.sub_dirs.sizes).copied()
            );
            init_and_set!(
                init_modified,
                self.files
                    .modified_times
                    .iter()
                    .chain(&self.sub_dirs.modified_times)
                    .map(|&t| t.into())
            );
            init_and_set!(
                init_accessed,
                self.files
                    .access_times
                    .iter()
                    .chain(&self.sub_dirs.access_times)
                    .map(|&t| t.into())
            );

            Ok(capnp::serialize::write_message_to_words(&msg))
        }

        pub fn get_file(&self, name: &str) -> Option<Vec<u8>> {
            let mut msg = capnp::message::Builder::new_default();
            let mut entry = msg
                .init_root::<crate::generated::metadata_capnp::directory_entry_metadata::Builder>();

            if let Some(&index) = self.file_map.get(name) {
                entry.set_name(self.files.names[index].clone());
                entry.set_size(self.files.sizes[index]);
                entry.set_modified(self.files.modified_times[index].into());
                entry.set_accessed(self.files.access_times[index].into());

                return Some(capnp::serialize::write_message_to_words(&msg));
            }

            None
        }
    }
}
