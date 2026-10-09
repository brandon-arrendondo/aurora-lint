use std::collections::BTreeSet;
use std::path::Path;

use git2::{Delta, Oid, Repository, Status, StatusOptions};
use walkdir::WalkDir;

use anyhow::{Context, Result};

pub struct GitRepo {
    repo: Repository,
    repo_path: String,
    /// The merge base `--diff-base` resolved to: when set, the files a
    /// branch changed since it count as modified too.
    diff_base: Option<Oid>,
}

impl GitRepo {
    pub fn open(path: &str) -> Result<Self> {
        let repo = Repository::open(path)
            .with_context(|| format!("Failed to open git repository at: {}", path))?;

        Ok(Self {
            repo,
            repo_path: path.to_string(),
            diff_base: None,
        })
    }

    /// Count the files changed between the merge base of `refname` and HEAD
    /// as modified, alongside the uncommitted ones. A pull-request checkout
    /// has no uncommitted changes, so without this a diff-only scan of one
    /// finds nothing. Resolved here, before any analysis, so a ref or a
    /// history the checkout lacks fails the run at once.
    pub fn set_diff_base(&mut self, refname: &str) -> Result<()> {
        let shallow = self.repo.is_shallow();
        let fetch_hint = if shallow {
            " This is a shallow clone: fetch the full history (`git fetch --unshallow`, or `fetch-depth: 0` in actions/checkout)."
        } else {
            ""
        };
        let base = self
            .repo
            .revparse_single(refname)
            .and_then(|o| o.peel_to_commit())
            .map_err(|_| {
                anyhow::anyhow!(
                    "--diff-base: '{refname}' does not name a commit in this repository. \
                     A CI checkout often holds only the branch being built: fetch the base \
                     first (e.g. `git fetch origin main`).{fetch_hint}"
                )
            })?;
        let head = self
            .repo
            .head()
            .and_then(|h| h.peel_to_commit())
            .context("--diff-base: HEAD does not name a commit")?;
        let merge_base = self.repo.merge_base(base.id(), head.id()).map_err(|_| {
            if shallow {
                anyhow::anyhow!(
                    "--diff-base: found no merge base of '{refname}' and HEAD. This is a \
                     shallow clone, so the history joining them was not fetched: fetch the \
                     full history (`git fetch --unshallow`, or `fetch-depth: 0` in actions/checkout)."
                )
            } else {
                anyhow::anyhow!("--diff-base: '{refname}' and HEAD share no history")
            }
        })?;
        self.diff_base = Some(merge_base);
        Ok(())
    }

    pub fn get_c_files(&self) -> Result<Vec<String>> {
        let mut c_files = Vec::new();

        for entry in WalkDir::new(&self.repo_path)
            .sort_by_file_name()
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

    /// The C files with uncommitted changes, staged or not, plus untracked
    /// ones; with a diff base set, also every file changed between it and
    /// HEAD. A renamed file counts under its new name, a deleted one not at
    /// all. Paths are joined to the repository path given, like
    /// [`Self::get_c_files`]'s, so they resolve from any directory.
    pub fn get_modified_c_files(&self) -> Result<Vec<String>> {
        let mut changed: BTreeSet<String> = BTreeSet::new();

        if let Some(base) = self.diff_base {
            let base_tree = self.repo.find_commit(base)?.tree()?;
            let head_tree = self.repo.head()?.peel_to_tree()?;
            let mut diff = self
                .repo
                .diff_tree_to_tree(Some(&base_tree), Some(&head_tree), None)
                .context("Failed to diff against the merge base")?;
            diff.find_similar(None)?;
            for delta in diff.deltas() {
                if delta.status() == Delta::Deleted {
                    continue;
                }
                if let Some(path) = delta.new_file().path().and_then(Path::to_str) {
                    changed.insert(path.to_string());
                }
            }
        }

        let mut status_options = StatusOptions::new();
        status_options.include_untracked(true);
        status_options.recurse_untracked_dirs(true);

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
                    changed.insert(path.to_string());
                }
            }
        }

        let root = Path::new(&self.repo_path);
        Ok(changed
            .into_iter()
            .filter(|p| {
                Path::new(p)
                    .extension()
                    .is_some_and(super::is_c_source_extension)
            })
            .map(|p| root.join(p))
            // Committed on the branch, then deleted and not yet committed.
            .filter(|p| p.is_file())
            .filter_map(|p| {
                p.to_str()
                    .map(|s| s.strip_prefix("./").unwrap_or(s).to_string())
            })
            .collect())
    }

    #[allow(dead_code)]
    pub fn get_repo_root(&self) -> &str {
        &self.repo_path
    }
}
