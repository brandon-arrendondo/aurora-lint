use git2::{Repository, Status, StatusOptions};
use walkdir::WalkDir;

use anyhow::{Context, Result};

pub struct GitRepo {
    repo: Repository,
    repo_path: String,
}

impl GitRepo {
    pub fn open(path: &str) -> Result<Self> {
        let repo = Repository::open(path)
            .with_context(|| format!("Failed to open git repository at: {}", path))?;

        Ok(Self {
            repo,
            repo_path: path.to_string(),
        })
    }

    pub fn get_c_files(&self) -> Result<Vec<String>> {
        let mut c_files = Vec::new();

        for entry in WalkDir::new(&self.repo_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if let Some(extension) = path.extension() {
                if super::is_c_source_extension(extension) {
                    if let Some(path_str) = path.to_str() {
                        // Skip files in .git directory
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
        let mut modified_files = Vec::new();
        let mut status_options = StatusOptions::new();
        status_options.include_untracked(true);

        let statuses = self
            .repo
            .statuses(Some(&mut status_options))
            .context("Failed to get repository status")?;

        for entry in statuses.iter() {
            let flags = entry.status();
            if flags.intersects(
                Status::WT_MODIFIED | Status::WT_NEW | Status::INDEX_MODIFIED | Status::INDEX_NEW,
            ) {
                if let Some(path) = entry.path() {
                    if path.ends_with(".c") || path.ends_with(".h") {
                        modified_files.push(path.to_string());
                    }
                }
            }
        }

        Ok(modified_files)
    }

    #[allow(dead_code)]
    pub fn get_repo_root(&self) -> &str {
        &self.repo_path
    }
}
