//! `#include` name lookup under the toolchain's matching rule.
//!
//! GCC and Clang on a POSIX file system find `<ShlObj.h>` only if a file of
//! exactly that name exists. cl on Windows finds it as `<Shlobj.h>` or
//! `SHLOBJ.H` too, because Windows looks file names up ignoring case. A
//! Windows project scanned on a Linux host therefore needs cl's rule, or
//! headers its own build finds are silently skipped
//! ([`IncludeNames::CaseInsensitive`]).
//!
//! Case-insensitive lookup reads each directory it passes through once and
//! keeps an index from folded name to the names actually on disk, so a
//! lookup costs a map probe rather than a `read_dir`. The index is always
//! consulted in that mode, never the file system's own matching: a drvfs
//! mount that already ignores case must give the same answer, and record the
//! same mismatches, as an ext4 one.
//!
//! Matching goes one path component at a time, so a directory spelled in
//! the wrong case (`<Sys/Types.h>`) is folded too. In each directory an entry
//! of exactly the written name wins, as it does on a case-sensitive NTFS
//! directory. Otherwise the entries that fold to the same name are the
//! candidates: several that are one file (xwin's lowercase symlinks beside
//! the real `ShlObj.h`) are not ambiguous; several different files are, and
//! the byte-wise smallest name is taken and the others reported, so the
//! choice is the same on every host and never silent.

use crate::settings::IncludeNames;
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

/// A header an `#include` name resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderMatch {
    /// The file found.
    pub path: PathBuf,
    /// Whether some component of the name was matched ignoring case: the
    /// build finds this file only on a toolchain that does.
    pub case_differs: bool,
    /// Other files the name matched equally well, when a directory held
    /// several different entries differing only in case. Empty unless
    /// `case_differs`.
    pub ambiguous_with: Vec<PathBuf>,
}

/// Folded entry name → the entry names on disk, sorted.
type DirIndex = HashMap<String, Vec<String>>;

/// The kind of entry a walk must end on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Want {
    File,
    Dir,
}

/// `path` split into its root (`/`, or a drive prefix and root) and the
/// rest, `/`-joined, for a walk from the root.
fn split_root(path: &Path) -> (PathBuf, String) {
    let mut root = PathBuf::new();
    let mut rest = Vec::new();
    for c in path.components() {
        match c {
            Component::RootDir | Component::Prefix(_) if rest.is_empty() => root.push(c),
            _ => rest.push(c.as_os_str().to_string_lossy().into_owned()),
        }
    }
    (root, rest.join("/"))
}

/// Whether two paths are one file: equal after resolving symlinks, or
/// spelled the same when either cannot be resolved.
fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// Looks `#include` names up under one [`IncludeNames`] rule. Cheap to
/// create; in the case-insensitive mode it caches one index per directory it
/// has read, for as long as it lives. Safe to share across threads (two
/// threads meeting a directory at once may both read it; either index is
/// the same).
#[derive(Debug, Default)]
pub struct HeaderLookup {
    mode: IncludeNames,
    /// Directory → its index, or `None` when it cannot be listed.
    dirs: Mutex<HashMap<PathBuf, Option<Arc<DirIndex>>>>,
    /// Files this lookup treats as absent, by canonical path: the
    /// build-generated headers withheld from code their configuration does
    /// not compile (`generated_headers`). A withheld match is no match, so
    /// the search goes on to the next directory, as a compiler's would if
    /// the file were not there.
    withheld: Option<Arc<HashSet<PathBuf>>>,
}

impl HeaderLookup {
    /// A lookup under `mode`.
    pub fn new(mode: IncludeNames) -> Self {
        Self {
            mode,
            dirs: Mutex::new(HashMap::new()),
            withheld: None,
        }
    }

    /// A lookup under the same rule that finds none of `withheld`.
    pub fn withholding(&self, withheld: Arc<HashSet<PathBuf>>) -> Self {
        Self {
            mode: self.mode,
            dirs: Mutex::new(HashMap::new()),
            withheld: Some(withheld),
        }
    }

    /// `found`, unless it is a file this lookup withholds.
    fn unless_withheld(&self, found: Option<HeaderMatch>) -> Option<HeaderMatch> {
        let Some(withheld) = self.withheld.as_ref() else {
            return found;
        };
        match found {
            Some(m)
                if withheld.contains(&m.path.canonicalize().unwrap_or_else(|_| m.path.clone())) =>
            {
                None
            }
            other => other,
        }
    }

    /// The rule this lookup applies.
    pub fn mode(&self) -> IncludeNames {
        self.mode
    }

    /// `name` in the form this rule compares: as written under exact
    /// matching, case-folded (and with cl's `\\` read as `/`) when the
    /// toolchain ignores case. Two names are the same file exactly when
    /// their keys are equal.
    pub fn key(&self, name: &str) -> String {
        match self.mode {
            IncludeNames::Exact => name.to_string(),
            IncludeNames::CaseInsensitive => fold(&name.replace('\\', "/")),
        }
    }

    /// Whether two file names written in `#include`s or on disk name the same
    /// file under this rule.
    pub fn same_name(&self, a: &str, b: &str) -> bool {
        match self.mode {
            IncludeNames::Exact => a == b,
            IncludeNames::CaseInsensitive => a == b || fold(a) == fold(b),
        }
    }

    /// Find `include_path` in `dir`. Exact mode joins and tests, as the
    /// resolver always has; case-insensitive mode walks the index. `/` and,
    /// for cl, `\` separate components. A search directory spelled in the
    /// wrong case is found too, since cl would find it; that spelling is the
    /// command line's, not the `#include`'s, so it is not a mismatch.
    pub fn find_in(&self, dir: &Path, include_path: &str) -> Option<HeaderMatch> {
        let found = match self.mode {
            IncludeNames::Exact => {
                let candidate = dir.join(include_path);
                candidate.is_file().then(|| HeaderMatch {
                    path: candidate,
                    case_differs: false,
                    ambiguous_with: Vec::new(),
                })
            }
            IncludeNames::CaseInsensitive => {
                let dir = self.search_dir(dir)?;
                self.walk_folded(&dir, include_path, Want::File)
            }
        };
        self.unless_withheld(found)
    }

    /// Whether `rel` names a directory under `root` under this rule.
    pub fn dir_exists(&self, root: &Path, rel: &Path) -> bool {
        match self.mode {
            IncludeNames::Exact => root.join(rel).is_dir(),
            IncludeNames::CaseInsensitive => self.search_dir(root).is_some_and(|root| {
                self.walk_folded(&root, &rel.to_string_lossy(), Want::Dir)
                    .is_some()
            }),
        }
    }

    /// Find an absolute `include_path` (a forced include the database named
    /// by full path). Case-insensitive mode walks it from the root through
    /// the index rather than asking the file system, which on a
    /// case-insensitive one (macOS, drvfs) would accept a wrong spelling
    /// without saying so.
    pub fn find_absolute(&self, include_path: &Path) -> Option<HeaderMatch> {
        let found = match self.mode {
            IncludeNames::Exact => include_path.is_file().then(|| HeaderMatch {
                path: include_path.to_path_buf(),
                case_differs: false,
                ambiguous_with: Vec::new(),
            }),
            IncludeNames::CaseInsensitive => {
                let (root, rest) = split_root(include_path);
                self.walk_folded(&root, &rest, Want::File)
            }
        };
        self.unless_withheld(found)
    }

    /// `dir` as spelled on disk. An absolute path is walked through the
    /// index, for the same reason as in [`find_absolute`](Self::find_absolute);
    /// a relative one, which has no root to walk from, is taken as written
    /// when it exists.
    fn search_dir(&self, dir: &Path) -> Option<PathBuf> {
        if dir.is_absolute() {
            let (root, rest) = split_root(dir);
            return self.walk_folded(&root, &rest, Want::Dir).map(|m| m.path);
        }
        dir.is_dir().then(|| dir.to_path_buf())
    }

    /// Follow `include_path` down from `dir` one component at a time,
    /// matching each ignoring case, to an entry of the kind `want` names. A
    /// name ending in a separator names no file.
    fn walk_folded(&self, dir: &Path, include_path: &str, want: Want) -> Option<HeaderMatch> {
        if want == Want::File && include_path.ends_with(['/', '\\']) {
            return None;
        }
        let parts: Vec<&str> = include_path
            .split(['/', '\\'])
            .filter(|p| !p.is_empty() && *p != ".")
            .collect();
        self.descend(dir.to_path_buf(), &parts, want, false)
    }

    /// One step of [`walk_folded`](Self::walk_folded). Every entry whose name
    /// folds to `parts[0]` is a candidate, the exact spelling first and then
    /// byte order; the first that leads to a `want` wins. Trying them all,
    /// rather than committing to one, is what a Windows checkout does: there
    /// `Sdk/` and `sdk/` are one directory, and a file of the right name
    /// beats a directory of it. An exact spelling that leads somewhere wins
    /// outright; otherwise every other candidate that leads to a different
    /// file is listed in `ambiguous_with`.
    fn descend(
        &self,
        at: PathBuf,
        parts: &[&str],
        want: Want,
        case_differs: bool,
    ) -> Option<HeaderMatch> {
        let Some((part, rest)) = parts.split_first() else {
            let found = match want {
                Want::File => at.is_file(),
                Want::Dir => at.is_dir(),
            };
            return found.then_some(HeaderMatch {
                path: at,
                case_differs,
                ambiguous_with: Vec::new(),
            });
        };
        if *part == ".." {
            return self.descend(at.join(part), rest, want, case_differs);
        }
        // A directory that can be entered but not listed (a 0711 home, a
        // sandbox) has no index to fold against: take the component as
        // written, which is all the file system can confirm there.
        let Some(index) = self.index(&at) else {
            return self.descend(at.join(part), rest, want, case_differs);
        };
        let names = index.get(&fold(part))?;
        let candidates = names
            .iter()
            .filter(|n| n.as_str() == *part)
            .chain(names.iter().filter(|n| n.as_str() != *part));
        let mut found: Option<HeaderMatch> = None;
        for name in candidates {
            let exact = name.as_str() == *part;
            let Some(hit) = self.descend(at.join(name), rest, want, case_differs || !exact) else {
                continue;
            };
            match &mut found {
                None if exact => return Some(hit),
                None => found = Some(hit),
                Some(first) => {
                    if !same_file(&first.path, &hit.path) {
                        first.ambiguous_with.push(hit.path);
                    }
                    first.ambiguous_with.extend(hit.ambiguous_with);
                }
            }
        }
        found
    }

    /// The index of `dir`, read on first use; `None` when it cannot be
    /// listed.
    fn index(&self, dir: &Path) -> Option<Arc<DirIndex>> {
        if let Some(i) = self.lock().get(dir) {
            return i.clone();
        }
        let index = std::fs::read_dir(dir).ok().map(|entries| {
            let mut index = DirIndex::new();
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    index.entry(fold(&name)).or_default().push(name);
                }
            }
            for names in index.values_mut() {
                names.sort();
            }
            Arc::new(index)
        });
        self.lock().insert(dir.to_path_buf(), index.clone());
        index
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<PathBuf, Option<Arc<DirIndex>>>> {
        // A panic elsewhere while the map was held leaves it consistent: every
        // write is one insert of a complete index.
        self.dirs.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// `name` with each character replaced by its uppercase form when that is a
/// single character: NTFS compares names through a one-to-one uppercase
/// table, so `ß` stays `ß` rather than becoming `SS`.
fn fold(name: &str) -> String {
    name.chars()
        .map(|c| {
            let mut upper = c.to_uppercase();
            match (upper.next(), upper.next()) {
                (Some(u), None) => u,
                _ => c,
            }
        })
        .collect()
}

/// Whether the file system temporary directories live on ignores case:
/// probed once, by creating `A` and looking for `a`.
#[cfg(test)]
pub(crate) fn temp_fs_ignores_case() -> bool {
    static IGNORES: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *IGNORES.get_or_init(|| {
        let dir = tempfile::tempdir().expect("a temporary directory");
        std::fs::write(dir.path().join("A"), "").expect("a probe file");
        dir.path().join("a").exists()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Whether the file system temporary directories live on ignores case
    /// (macOS APFS, drvfs), where two names differing only in case are one
    /// file and an exact-case lookup finds any spelling. Tests that need
    /// either to be otherwise skip there, saying so.
    fn temp_fs_ignores_case() -> bool {
        super::temp_fs_ignores_case()
    }

    fn skip(test: &str) -> bool {
        let ignores = temp_fs_ignores_case();
        if ignores {
            eprintln!("{test}: skipped, the temporary directory's file system ignores case");
        }
        ignores
    }

    fn tree(files: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for f in files {
            let p = dir.path().join(f);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, "").unwrap();
        }
        dir
    }

    #[test]
    fn exact_mode_needs_the_exact_name() {
        let dir = tree(&["ShlObj.h"]);
        let lookup = HeaderLookup::new(IncludeNames::Exact);
        // Exact matching takes the file system's answer, which on a
        // case-insensitive one accepts any spelling.
        if !skip("exact_mode_needs_the_exact_name: the miss") {
            assert!(lookup.find_in(dir.path(), "Shlobj.h").is_none());
        }
        let hit = lookup.find_in(dir.path(), "ShlObj.h").unwrap();
        assert!(!hit.case_differs);
    }

    #[test]
    fn case_insensitive_mode_finds_another_spelling_and_says_so() {
        let dir = tree(&["ShlObj.h"]);
        let lookup = HeaderLookup::new(IncludeNames::CaseInsensitive);
        let hit = lookup.find_in(dir.path(), "Shlobj.h").unwrap();
        assert_eq!(hit.path, dir.path().join("ShlObj.h"));
        assert!(hit.case_differs);
        assert!(hit.ambiguous_with.is_empty());
        let hit = lookup.find_in(dir.path(), "SHLOBJ.H").unwrap();
        assert_eq!(hit.path, dir.path().join("ShlObj.h"));
        let exact = lookup.find_in(dir.path(), "ShlObj.h").unwrap();
        assert!(!exact.case_differs);
    }

    #[test]
    fn directory_components_fold_too_and_backslash_separates() {
        let dir = tree(&["sys/Types.h"]);
        let lookup = HeaderLookup::new(IncludeNames::CaseInsensitive);
        let hit = lookup.find_in(dir.path(), "SYS/types.h").unwrap();
        assert_eq!(hit.path, dir.path().join("sys").join("Types.h"));
        let hit = lookup.find_in(dir.path(), "Sys\\TYPES.h").unwrap();
        assert_eq!(hit.path, dir.path().join("sys").join("Types.h"));
        assert!(
            lookup.find_in(dir.path(), "sys").is_none(),
            "a directory is not a header"
        );
    }

    #[test]
    fn parent_components_are_followed() {
        let dir = tree(&["inc/A.h", "src/x.c"]);
        let lookup = HeaderLookup::new(IncludeNames::CaseInsensitive);
        let hit = lookup
            .find_in(&dir.path().join("src"), "../INC/a.h")
            .unwrap();
        assert!(hit.path.is_file());
        assert!(hit.case_differs);
    }

    #[test]
    fn an_exact_entry_wins_over_case_variants() {
        // Needs two entries whose names differ only in case.
        if skip("an_exact_entry_wins_over_case_variants") {
            return;
        }
        let dir = tree(&["config.h", "Config.h"]);
        let lookup = HeaderLookup::new(IncludeNames::CaseInsensitive);
        let hit = lookup.find_in(dir.path(), "Config.h").unwrap();
        assert_eq!(hit.path, dir.path().join("Config.h"));
        assert!(!hit.case_differs);
        assert!(hit.ambiguous_with.is_empty());
    }

    #[test]
    fn different_files_differing_only_in_case_are_ambiguous_and_the_pick_is_stable() {
        // Needs two entries whose names differ only in case.
        if skip("different_files_differing_only_in_case_are_ambiguous_and_the_pick_is_stable") {
            return;
        }
        let dir = tree(&["config.h", "Config.h"]);
        let lookup = HeaderLookup::new(IncludeNames::CaseInsensitive);
        let hit = lookup.find_in(dir.path(), "CONFIG.H").unwrap();
        // Byte order: uppercase sorts first.
        assert_eq!(hit.path, dir.path().join("Config.h"));
        assert!(hit.case_differs);
        assert_eq!(hit.ambiguous_with, vec![dir.path().join("config.h")]);
    }

    #[cfg(unix)]
    #[test]
    fn case_variants_that_are_one_file_are_not_ambiguous() {
        // Needs two entries whose names differ only in case.
        if skip("case_variants_that_are_one_file_are_not_ambiguous") {
            return;
        }
        // xwin's layout: the real mixed-case header plus a lowercase symlink.
        let dir = tree(&["ShlObj.h"]);
        std::os::unix::fs::symlink("ShlObj.h", dir.path().join("shlobj.h")).unwrap();
        let lookup = HeaderLookup::new(IncludeNames::CaseInsensitive);
        let hit = lookup.find_in(dir.path(), "Shlobj.h").unwrap();
        assert!(hit.case_differs);
        assert!(hit.ambiguous_with.is_empty());
    }

    #[test]
    fn absolute_names_fold_from_the_root() {
        let dir = tree(&["Sdk/Idx.h"]);
        let lookup = HeaderLookup::new(IncludeNames::CaseInsensitive);
        let written = dir.path().join("sdk").join("IDX.h");
        let hit = lookup.find_absolute(&written).unwrap();
        assert_eq!(hit.path, dir.path().join("Sdk").join("Idx.h"));
        if !skip("absolute_names_fold_from_the_root: the exact miss") {
            assert!(HeaderLookup::new(IncludeNames::Exact)
                .find_absolute(&written)
                .is_none());
        }
    }

    #[test]
    fn a_directory_is_read_once() {
        let dir = tree(&["A.h"]);
        let lookup = HeaderLookup::new(IncludeNames::CaseInsensitive);
        assert!(lookup.find_in(dir.path(), "a.h").is_some());
        // A file added after the first read is not seen: the index is the
        // directory as first read, which is what makes a lookup a map probe.
        fs::write(dir.path().join("B.h"), "").unwrap();
        assert!(lookup.find_in(dir.path(), "b.h").is_none());
    }

    #[test]
    fn directories_are_found_for_the_missing_header_check() {
        let dir = tree(&["include/object/a.h"]);
        let ci = HeaderLookup::new(IncludeNames::CaseInsensitive);
        assert!(ci.dir_exists(&dir.path().join("include"), Path::new("Object")));
        assert!(!ci.dir_exists(&dir.path().join("include"), Path::new("object/a.h")));
        let exact = HeaderLookup::new(IncludeNames::Exact);
        if !skip("directories_are_found_for_the_missing_header_check: the exact miss") {
            assert!(!exact.dir_exists(&dir.path().join("include"), Path::new("Object")));
        }
        assert!(exact.dir_exists(&dir.path().join("include"), Path::new("object")));
    }

    #[test]
    fn an_entry_of_the_wrong_kind_does_not_hide_the_header() {
        // Needs two entries whose names differ only in case.
        if skip("an_entry_of_the_wrong_kind_does_not_hide_the_header") {
            return;
        }
        // A directory `Config.h/` sorts before the file `config.h`.
        let dir = tree(&["Config.h/x", "config.h"]);
        let lookup = HeaderLookup::new(IncludeNames::CaseInsensitive);
        let hit = lookup.find_in(dir.path(), "CONFIG.H").unwrap();
        assert_eq!(hit.path, dir.path().join("config.h"));
        assert!(hit.ambiguous_with.is_empty());
    }

    #[test]
    fn directories_differing_only_in_case_are_searched_as_one() {
        // Needs two entries whose names differ only in case.
        if skip("directories_differing_only_in_case_are_searched_as_one") {
            return;
        }
        // On a Windows checkout `Sdk/` and `sdk/` are one directory.
        let dir = tree(&["Sdk/other.h", "sdk/c.h"]);
        let lookup = HeaderLookup::new(IncludeNames::CaseInsensitive);
        let hit = lookup.find_in(dir.path(), "SDK/c.h").unwrap();
        assert_eq!(hit.path, dir.path().join("sdk").join("c.h"));
        assert!(hit.ambiguous_with.is_empty());
        // The same name under both is ambiguous, and names the files. A
        // fresh lookup: the first one's index of the temporary directory's
        // parent predates this tree.
        let dir = tree(&["Sdk/c.h", "sdk/c.h"]);
        let lookup = HeaderLookup::new(IncludeNames::CaseInsensitive);
        let hit = lookup.find_in(dir.path(), "SDK/c.h").unwrap();
        assert_eq!(hit.path, dir.path().join("Sdk").join("c.h"));
        assert_eq!(hit.ambiguous_with, vec![dir.path().join("sdk").join("c.h")]);
    }

    #[test]
    fn a_trailing_separator_names_no_file() {
        let dir = tree(&["inc/a.h"]);
        let lookup = HeaderLookup::new(IncludeNames::CaseInsensitive);
        assert!(lookup.find_in(dir.path(), "INC/a.h/").is_none());
        assert!(lookup.find_in(dir.path(), "INC\\a.h\\").is_none());
    }

    #[test]
    fn a_search_directory_spelled_in_another_case_is_found() {
        let dir = tree(&["Inc/a.h"]);
        let lookup = HeaderLookup::new(IncludeNames::CaseInsensitive);
        let hit = lookup.find_in(&dir.path().join("inc"), "a.h").unwrap();
        assert_eq!(hit.path, dir.path().join("Inc").join("a.h"));
        assert!(
            !hit.case_differs,
            "the command line's spelling is not the #include's"
        );
        if !skip("a_search_directory_spelled_in_another_case_is_found: the exact miss") {
            assert!(HeaderLookup::new(IncludeNames::Exact)
                .find_in(&dir.path().join("inc"), "a.h")
                .is_none());
        }
    }

    #[test]
    fn an_absolute_name_with_a_parent_component_folds() {
        let dir = tree(&["Sdk/Idx.h", "src/x.c"]);
        let lookup = HeaderLookup::new(IncludeNames::CaseInsensitive);
        let written = dir.path().join("SRC").join("..").join("sdk").join("idx.h");
        let hit = lookup.find_absolute(&written).unwrap();
        assert!(hit.path.is_file());
        assert!(hit.case_differs);
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_that_cannot_be_listed_is_passed_through_as_written() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tree(&["locked/inc/A.h"]);
        let locked = dir.path().join("locked");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o711)).unwrap();
        // Root reads any directory, so there is nothing to test as root.
        let listable = fs::read_dir(&locked).is_ok();
        let lookup = HeaderLookup::new(IncludeNames::CaseInsensitive);
        let search = locked.join("inc");
        let hit = lookup.find_in(&search, "a.h");
        let spelled = lookup.find_in(&locked.join("INC"), "a.h");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        if listable {
            eprintln!("a_directory_that_cannot_be_listed...: skipped, running as root");
            return;
        }
        let hit = hit.expect("found through the unlistable parent");
        assert_eq!(hit.path, search.join("A.h"));
        // Below it, case is still folded; at it, only the written spelling
        // can be confirmed.
        if !temp_fs_ignores_case() {
            assert!(spelled.is_none());
        }
    }

    #[test]
    fn folding_is_one_to_one() {
        assert_eq!(fold("ShlObj.h"), "SHLOBJ.H");
        assert_eq!(fold("straße.h"), "STRAßE.H");
        let lookup = HeaderLookup::new(IncludeNames::CaseInsensitive);
        assert!(lookup.same_name("Foo.C", "foo.c"));
        assert!(!HeaderLookup::new(IncludeNames::Exact).same_name("Foo.C", "foo.c"));
    }
}
