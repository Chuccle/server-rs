pub mod metadata {

    #[derive(Debug, Clone, serde::Serialize)]
    pub struct DirEntMeta {
        name: String,
        size: u64,
        modified: crate::utils::windows::time::FileTime,
        accessed: crate::utils::windows::time::FileTime,
    }

    #[derive(Debug, Clone, Copy, serde::Serialize)]
    pub struct DirEntMetaFull<'a> {
        is_dir: bool,
        #[serde(borrow)]
        info: &'a DirEntMeta,
    }

    pub fn create_direntmeta(
        meta: &std::fs::Metadata,
        name: &str,
    ) -> Result<DirEntMeta, std::io::Error> {
        Ok(DirEntMeta {
            name: name.to_string(),
            size: meta.len(),
            modified: meta.modified()?.into(),
            accessed: meta.accessed()?.into(),
        })
    }

    #[derive(Debug, Clone)]
    pub struct DirectoryLookupContext {
        // Contiguous storage for cache efficiency
        files: Vec<DirEntMeta>,
        sub_dirs: Vec<DirEntMeta>,
        // Fast lookup
        file_map: std::collections::HashMap<String, usize>, // Maps filename -> index in files
        sub_dir_map: std::collections::HashMap<String, usize>, // Maps sub_dir -> index in files
    }

    impl DirectoryLookupContext {
        pub fn new() -> Self {
            Self {
                files: Vec::new(),
                sub_dirs: Vec::new(),
                file_map: std::collections::HashMap::new(),
                sub_dir_map: std::collections::HashMap::new(),
            }
        }

        pub fn add_file(&mut self, file: DirEntMeta) {
            self.file_map.insert(file.name.clone(), self.files.len());
            self.files.push(file);
        }

        pub fn add_subdir(&mut self, dir: DirEntMeta) {
            self.sub_dir_map
                .insert(dir.name.clone(), self.sub_dirs.len());
            self.sub_dirs.push(dir);
        }

        // Get all files in this directory (non-recursive)
        pub fn get_files(&self) -> &[DirEntMeta] {
            &self.files
        }

        // Get all subdirectories in this directory (non-recursive)
        pub fn get_subdirs(&self) -> &[DirEntMeta] {
            &self.sub_dirs
        }

        pub fn get_all_entries(&self) -> impl Iterator<Item = DirEntMetaFull<'_>> {
            self.sub_dirs
                .iter()
                .map(|sub_dir| DirEntMetaFull {
                    is_dir: true,
                    info: sub_dir,
                })
                .chain(self.files.iter().map(|file| DirEntMetaFull {
                    is_dir: false,
                    info: file,
                }))
        }

        pub fn get_file(&self, name: &str) -> Option<&DirEntMeta> {
            self.file_map.get(name).map(|&index| &self.files[index])
        }

        pub fn get_subdir(&self, name: &str) -> Option<&DirEntMeta> {
            self.sub_dir_map
                .get(name)
                .map(|&index| &self.sub_dirs[index])
        }
    }
}
