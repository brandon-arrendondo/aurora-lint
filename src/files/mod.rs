mod directory;
mod git;

use directory::DirectorySource;
use git::GitRepo;

use anyhow::Result;

/// Whether `ext` is a C source/header extension sqc analyzes.
///
/// Deliberately NOT `lang_parsing_substrate::is_parseable_extension`: that
/// function reflects every language feature compiled into the substrate,
/// including `lang-cpp` (enabled solely for `cpp_header::looks_like_cpp`,
/// task 571's C++-header detection) — using it here would silently widen
/// file discovery to `.cpp`/`.hpp`/etc. and run C-only rules against real
/// C++ source across every project, not just the one ambiguous `.h` case
/// task 571 targets. `is_extension_for_language` (substrate 0.5.2+, task
/// 583) is the fix upstream: scoped to the `"c"` key specifically, so it
/// can never change just because another `lang-*` feature gets enabled.
pub(crate) fn is_c_source_extension(ext: &std::ffi::OsStr) -> bool {
    lang_parsing_substrate::is_extension_for_language(ext, "c")
}

/// Where the project's C files are being read from.
pub enum ProjectSource {
    /// A git repository (enables `get_modified_c_files`/diff-only scoping).
    Git(GitRepo),
    /// A plain directory or single file, with no git history available.
    Directory(DirectorySource),
}

impl ProjectSource {
    /// Open `path`, preferring a git repository and falling back to a plain
    /// directory/file source if `path` isn't inside one.
    pub fn open(path: &str) -> Result<Self> {
        // First try to open as a git repository
        if let Ok(git_repo) = GitRepo::open(path) {
            Ok(ProjectSource::Git(git_repo))
        } else {
            // Fall back to directory source
            let dir_source = DirectorySource::open(path)?;
            Ok(ProjectSource::Directory(dir_source))
        }
    }

    /// Every C file in this source.
    pub fn get_c_files(&self) -> Result<Vec<String>> {
        match self {
            ProjectSource::Git(git_repo) => git_repo.get_c_files(),
            ProjectSource::Directory(dir_source) => dir_source.get_c_files(),
        }
    }

    /// C files changed relative to the source's baseline (git diff for a
    /// [`ProjectSource::Git`], all files for a [`ProjectSource::Directory`]).
    pub fn get_modified_c_files(&self) -> Result<Vec<String>> {
        match self {
            ProjectSource::Git(git_repo) => git_repo.get_modified_c_files(),
            ProjectSource::Directory(dir_source) => dir_source.get_modified_c_files(),
        }
    }

    /// This source's root path.
    #[allow(dead_code)]
    pub fn get_root_path(&self) -> &str {
        match self {
            ProjectSource::Git(git_repo) => git_repo.get_repo_root(),
            ProjectSource::Directory(dir_source) => dir_source.get_root_path(),
        }
    }

    /// Returns the directory to pre-scan for cross-file context, if applicable.
    ///
    /// Returns Some(dir) when the target is a single `.c` file so that sibling
    /// headers are included in the prescan. Returns None for directory/git targets
    /// (the caller already knows the root to scan).
    pub fn prescan_dir(&self) -> Option<String> {
        match self {
            ProjectSource::Git(_) => None,
            ProjectSource::Directory(dir_source) => dir_source.prescan_dir(),
        }
    }

    /// A short label for this source's kind: `"git repository"`, `"file"`,
    /// or `"directory"`.
    pub fn source_type(&self) -> &str {
        match self {
            ProjectSource::Git(_) => "git repository",
            ProjectSource::Directory(dir_source) => {
                if dir_source.is_file() {
                    "file"
                } else {
                    "directory"
                }
            }
        }
    }
}
