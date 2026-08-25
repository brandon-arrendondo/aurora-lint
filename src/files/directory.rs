use anyhow::Result;
use std::path::Path;
use walkdir::WalkDir;

pub struct DirectorySource {
    path: String,
    is_file: bool,
}

impl DirectorySource {
    pub fn open(path: &str) -> Result<Self> {
        let path_obj = Path::new(path);
        if !path_obj.exists() {
            return Err(anyhow::anyhow!("Path does not exist: {}", path));
        }

        let is_file = path_obj.is_file();
        let is_dir = path_obj.is_dir();

        if !is_file && !is_dir {
            return Err(anyhow::anyhow!(
                "Path is neither a file nor a directory: {}",
                path
            ));
        }

        // If it's a file, verify it has a C source/header extension.
        if is_file {
            let parseable = path_obj
                .extension()
                .map(super::is_c_source_extension)
                .unwrap_or(false);
            if !parseable {
                return Err(anyhow::anyhow!(
                    "File must have .c or .h extension: {}",
                    path
                ));
            }
        }

        Ok(Self {
            path: path.to_string(),
            is_file,
        })
    }

    pub fn get_c_files(&self) -> Result<Vec<String>> {
        let mut c_files = Vec::new();

        // If it's a single file, just return the path as given
        if self.is_file {
            c_files.push(self.path.clone());
            return Ok(c_files);
        }

        // Otherwise, walk the directory
        for entry in WalkDir::new(&self.path).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if let Some(extension) = path.extension() {
                if super::is_c_source_extension(extension) {
                    if let Some(path_str) = path.to_str() {
                        // Skip files in .git directory (in case there's a .git folder but not a valid repo)
                        if !path_str.contains("/.git/") {
                            // Normalize: strip leading "./" so paths are clean relative to cwd
                            let normalized = path_str.strip_prefix("./").unwrap_or(path_str);
                            c_files.push(normalized.to_string());
                        }
                    }
                }
            }
        }

        Ok(c_files)
    }

    pub fn get_modified_c_files(&self) -> Result<Vec<String>> {
        // For non-git directories, return all C files as "modified"
        // since we don't have version control information
        self.get_c_files()
    }

    #[allow(dead_code)]
    pub fn get_root_path(&self) -> &str {
        &self.path
    }

    pub fn is_file(&self) -> bool {
        self.is_file
    }

    /// Returns the directory to pre-scan for cross-file context.
    ///
    /// For a single-file target, this is the file's parent directory so that
    /// sibling headers are included in the prescan (enabling rules like DCL15-C
    /// to recognise public API declared in those headers).
    /// For a directory target, returns None (the caller already has the dir).
    pub fn prescan_dir(&self) -> Option<String> {
        if self.is_file {
            let parent = std::path::Path::new(&self.path)
                .parent()
                .and_then(|p| p.to_str())
                .map(|s| if s.is_empty() { "." } else { s });
            parent.map(|s| s.to_string())
        } else {
            None
        }
    }
}
