//! Build-generated headers, and the code their configuration compiles
//! (`docs/design/generated-headers-and-configuration.md`).
//!
//! A build generates some headers for the one configuration it was run in:
//! declaration lists, inline function bodies, configuration values. Read as
//! true for every scanned file, they pair one configuration's facts with code
//! only another configuration compiles: calls reported as undeclared because
//! this configuration's header lacks a declaration another one generates
//! (ADR-0005), array sizes from one configuration meeting code from another
//! (ADR-0010 Decision 4), callee bodies borrowed across configurations
//! (Decision 8).
//!
//! So a scan with generated headers builds its cross-file context twice from
//! one prescan: once with every header (for the files the configuration
//! compiles) and once with the generated ones withheld (for every other
//! file), which is exactly the context the scan would have had if they were
//! missing. This module decides the two inputs that split needs, both from
//! what the user or the build declared and never from a file name:
//!
//! - **Which headers are generated.** Every file under a directory given with
//!   `--generated-include` (R1), and under each compile-database include
//!   directory that lies inside the working directory of an entry compiling
//!   a file outside it, or compiling a unit there that names sources outside
//!   it -- an out-of-source build tree -- and outside every project root (R2), except a byte-identical
//!   copy of a project file, which is that project header.
//! - **Which `.c` files the configuration compiles.** The database's
//!   translation units, files one of them names in a `#line` directive (a
//!   build that concatenates its sources into one generated unit), and `.c`
//!   files one of them `#include`s (a unity build).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use walkdir::WalkDir;

use super::compile_commands::{real_path, CompileDb};

/// The build-generated headers this scan recognised.
#[derive(Debug, Clone, Default)]
pub struct GeneratedHeaders {
    /// The directories they were found under, as given or as the database
    /// names them, sorted.
    pub dirs: Vec<String>,
    /// Every file under those directories, by canonical path: the files a
    /// scan withholds from code their configuration does not compile.
    pub files: Arc<HashSet<PathBuf>>,
}

impl GeneratedHeaders {
    /// Recognise the generated headers of this scan: under `declared` (R1)
    /// and under the database's build-tree include directories outside
    /// `project_roots` (R2). `None` when there are none, which leaves the
    /// scan exactly as it is without this module.
    ///
    /// A declared directory inside a project root is refused: the prescan
    /// reads everything under the roots as source, so its files would reach
    /// every file's context whatever this module decided.
    pub fn recognise(
        declared: &[String],
        db: Option<&CompileDb>,
        project_roots: &[String],
    ) -> Result<Option<Self>> {
        let roots: Vec<PathBuf> = project_roots
            .iter()
            .map(|r| canonical(Path::new(r)))
            .collect();
        let under_a_root = |dir: &Path| roots.iter().any(|r| dir.starts_with(r));

        let mut dirs: Vec<String> = Vec::new();
        for dir in declared {
            let path = Path::new(dir);
            if !path.is_dir() {
                anyhow::bail!("--generated-include {dir}: not a directory");
            }
            if under_a_root(&canonical(path)) {
                anyhow::bail!(
                    "--generated-include {dir}: the directory is inside the scanned tree, \
                     whose files are all read as source; name a build tree outside it"
                );
            }
            dirs.push(dir.clone());
        }
        let mut build_trees: Vec<PathBuf> = Vec::new();
        if let Some(db) = db {
            // Only an include directory outside every project root can be the
            // build's output; with none, nothing below is read.
            let outside: Vec<(&String, PathBuf)> = db
                .include_paths
                .iter()
                .map(|inc| (inc, canonical(Path::new(inc))))
                .filter(|(_, path)| path.is_dir() && !under_a_root(path))
                .collect();
            if !outside.is_empty() {
                // A directory is a build tree when an entry run there compiles
                // a file elsewhere, or compiles a unit it generated that names
                // sources elsewhere (a concatenated or unity build). Only a
                // unit whose directory holds one of those include directories
                // is read.
                let generated_unit_dirs = db.in_place_units.iter().filter_map(|(dir, file)| {
                    let dir = canonical(Path::new(dir));
                    if !outside.iter().any(|(_, inc)| inc.starts_with(&dir)) {
                        return None;
                    }
                    unit_named_sources(Path::new(file))
                        .iter()
                        .any(|named| !Path::new(named).starts_with(&dir))
                        .then_some(dir)
                });
                build_trees = db
                    .build_trees
                    .iter()
                    .map(|d| canonical(Path::new(d)))
                    .chain(generated_unit_dirs)
                    .filter(|d| !under_a_root(d))
                    .collect();
                for (inc, path) in &outside {
                    if build_trees.iter().any(|t| path.starts_with(t)) {
                        dirs.push((*inc).clone());
                    }
                }
            }
        }
        dirs.sort();
        dirs.dedup();

        let mut candidates: Vec<PathBuf> = Vec::new();
        for dir in &dirs {
            for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    candidates.push(canonical(entry.path()));
                }
            }
        }
        candidates.sort();
        candidates.dedup();
        let copies = copies_of_project_files(&candidates, &roots, &build_trees);
        let files: HashSet<PathBuf> = candidates
            .into_iter()
            .filter(|f| !copies.contains(f))
            .collect();
        if files.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self {
            dirs,
            files: Arc::new(files),
        }))
    }

    /// A fingerprint of the withheld set, for a prescan cache to record: a
    /// context split around one set of generated headers is not the context
    /// for another.
    pub fn fingerprint(&self) -> String {
        let mut paths: Vec<String> = self
            .files
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        paths.sort();
        crate::utility::hash::sha256_hex(paths.join("\n").as_bytes())
    }
}

/// The `candidates` whose bytes equal some file's under `roots`: a build step
/// that copies the project's own headers into its build tree (a public
/// header staged for installation, a source tree staged for a later step)
/// generates nothing, so a copy is an ordinary project header. Only project
/// files of a size some candidate has are read; version-control metadata and
/// the build trees themselves are not project files.
fn copies_of_project_files(
    candidates: &[PathBuf],
    roots: &[PathBuf],
    build_trees: &[PathBuf],
) -> HashSet<PathBuf> {
    let size = |p: &Path| std::fs::metadata(p).map(|m| m.len()).ok();
    let mut by_size: std::collections::HashMap<u64, Vec<&PathBuf>> = Default::default();
    for c in candidates {
        if let Some(n) = size(c) {
            by_size.entry(n).or_default().push(c);
        }
    }
    let digest = |p: &Path| {
        std::fs::read(p)
            .ok()
            .map(|b| crate::utility::hash::sha256_hex(&b))
    };
    let mut project_digests: HashSet<String> = HashSet::new();
    for root in roots {
        // A build tree is outside every root by construction, so skipping it
        // matters only for a root that lies inside one (a scan of a source
        // tree copied under the build directory).
        let walk = WalkDir::new(root).into_iter().filter_entry(|e| {
            e.file_name() != ".git" && !build_trees.iter().any(|t| e.path().starts_with(t))
        });
        for entry in walk.filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if size(path).is_some_and(|n| by_size.contains_key(&n)) {
                if let Some(d) = digest(path) {
                    project_digests.insert(d);
                }
            }
        }
    }
    candidates
        .iter()
        .filter(|c| digest(c).is_some_and(|d| project_digests.contains(&d)))
        .cloned()
        .collect()
}

/// The `.c` files the database's configuration compiles, by real path, and
/// for those holding arms it does not compile, which lines it does.
#[derive(Debug, Clone, Default)]
pub struct Membership {
    members: HashSet<String>,
    /// A member file whose excluded or undecided arms hold code naming
    /// something a generated header defines -> its lines, `true` where the
    /// configuration compiles them (`configuration_arms::compiled_lines`).
    arms: std::collections::HashMap<String, Arc<Vec<bool>>>,
}

impl Membership {
    /// The database's translation units, the files those units name in a
    /// `#line` directive, and the `.c` files they `#include` (transitively,
    /// through `include_edges`, keyed by real path as the prescan keys them).
    pub fn of(
        db: &CompileDb,
        include_edges: &std::collections::HashMap<String, Vec<String>>,
    ) -> Self {
        let mut members: HashSet<String> = db.configured_sources.clone();
        for tu in &db.configured_sources {
            for named in unit_named_sources(Path::new(tu)) {
                members.insert(named);
            }
        }
        let mut stack: Vec<String> = db.configured_sources.iter().cloned().collect();
        let mut seen: HashSet<String> = stack.iter().cloned().collect();
        while let Some(file) = stack.pop() {
            for next in include_edges.get(&file).into_iter().flatten() {
                if seen.insert(next.clone()) {
                    if next.ends_with(".c") {
                        members.insert(next.clone());
                    }
                    stack.push(next.clone());
                }
            }
        }
        Self {
            members,
            arms: Default::default(),
        }
    }

    /// Whether the configuration compiles `path`.
    pub fn contains(&self, path: &Path) -> bool {
        self.members.contains(&real_path(path))
    }

    /// For a member file with arms the configuration does not compile that
    /// could read generated facts, its compiled lines (indexed from 1).
    pub fn arms_of(&self, path: &Path) -> Option<&Arc<Vec<bool>>> {
        self.arms.get(&real_path(path))
    }

    /// Whether any member file is split by arm.
    pub fn has_arms(&self) -> bool {
        !self.arms.is_empty()
    }

    /// How many member files are split by arm.
    pub fn arms_len(&self) -> usize {
        self.arms.len()
    }

    /// Decide, for each scanned member file, which of its lines the
    /// configuration compiles (§4.2, M2), keeping the files whose excluded
    /// lines name something `generated` defines. The configuration's macro
    /// state is read from the database, the generated headers and the
    /// project headers the member files reach (`include_edges`).
    pub fn with_arms(
        mut self,
        db: Option<&CompileDb>,
        generated: &GeneratedHeaders,
        include_edges: &std::collections::HashMap<String, Vec<String>>,
        outside_headers: &[String],
        scanned: &[String],
    ) -> Self {
        // System headers are read for their declarations, not for the
        // configuration: a name only they define is left to the closed world.
        let outside_headers: HashSet<&str> = outside_headers.iter().map(String::as_str).collect();
        let mut generated_names: HashSet<String> = HashSet::new();
        for f in generated.files.iter() {
            if let Ok(text) = std::fs::read_to_string(f) {
                generated_names.extend(super::configuration_arms::names_defined_in(&text));
            }
        }
        let mut headers: HashSet<String> = HashSet::new();
        let mut stack: Vec<String> = self.members.iter().cloned().collect();
        let mut seen: HashSet<String> = stack.iter().cloned().collect();
        while let Some(file) = stack.pop() {
            for next in include_edges.get(&file).into_iter().flatten() {
                if seen.insert(next.clone()) {
                    if !next.ends_with(".c")
                        && !generated.files.contains(Path::new(next))
                        && !outside_headers.contains(next.as_str())
                    {
                        headers.insert(next.clone());
                    }
                    stack.push(next.clone());
                }
            }
        }
        let state = super::configuration_arms::ConfigState::build(
            db,
            generated.files.iter().map(PathBuf::as_path),
            headers.iter().map(Path::new),
        );
        for file in scanned.iter().filter(|f| f.ends_with(".c")) {
            let key = real_path(Path::new(file));
            if !self.members.contains(&key) {
                continue;
            }
            let Ok(source) = std::fs::read_to_string(file) else {
                continue;
            };
            let compiled = super::configuration_arms::compiled_lines(&source, &state);
            if super::configuration_arms::excludes_code_naming(&source, &compiled, &generated_names)
            {
                self.arms.insert(key, Arc::new(compiled));
            }
        }
        self
    }
}

/// The `.c` files a translation unit names in `#line N "file"` directives
/// and in quoted `#include`s, by real path; relative
/// names are read against the unit's own directory. A build that
/// concatenates its sources into one generated unit marks each with a
/// `#line`, and a unity build joins them by `#include`. Read from the unit
/// itself because a generated unit lies outside the scanned tree, so the
/// scan never parses it for include edges.
fn unit_named_sources(tu: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(tu) else {
        return Vec::new();
    };
    let dir = tu.parent().unwrap_or(Path::new("."));
    let resolve = |name: &str| {
        let path = Path::new(name);
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            dir.join(path)
        };
        path.is_file().then(|| real_path(&path))
    };
    let quoted = |rest: &str| {
        rest.trim()
            .strip_prefix('"')
            .and_then(|r| r.split('"').next())
            .map(str::to_string)
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.trim_start().strip_prefix('#') else {
            continue;
        };
        let rest = rest.trim_start();
        if let Some(rest) = rest.strip_prefix("line") {
            let mut parts = rest.trim_start().splitn(2, char::is_whitespace);
            if !parts
                .next()
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            {
                continue;
            }
            // A source, not a grammar or template a generator names (a
            // parser generator's `#line "../parse.y"`).
            if let Some(found) = parts
                .next()
                .and_then(quoted)
                .filter(|n| n.ends_with(".c"))
                .and_then(|n| resolve(&n))
            {
                out.push(found);
            }
        } else if let Some(rest) = rest.strip_prefix("include") {
            if let Some(name) = quoted(rest).filter(|n| n.ends_with(".c")) {
                if let Some(found) = resolve(&name) {
                    out.push(found);
                }
            }
        }
    }
    out
}

fn canonical(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_directives_name_the_concatenated_sources() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.c"), "int a;\n").unwrap();
        std::fs::write(dir.path().join("b.c"), "int b;\n").unwrap();
        let tu = dir.path().join("all.c");
        std::fs::write(
            &tu,
            format!(
                "#line 1 \"{}\"\nint a;\n# line 7 \"b.c\"\nint b;\n#line 3\n#line x \"no.c\"\n",
                dir.path().join("a.c").display()
            ),
        )
        .unwrap();
        let mut found = unit_named_sources(&tu);
        found.sort();
        let mut want = vec![
            real_path(&dir.path().join("a.c")),
            real_path(&dir.path().join("b.c")),
        ];
        want.sort();
        assert_eq!(found, want);
    }

    #[test]
    fn a_unity_unit_names_the_sources_it_includes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.c"), "int a;\n").unwrap();
        std::fs::write(dir.path().join("a.h"), "int h;\n").unwrap();
        let tu = dir.path().join("unity.c");
        std::fs::write(
            &tu,
            format!(
                "/* generated */\n#include \"{}\"\n#include \"a.h\"\n#include <b.c>\n",
                dir.path().join("a.c").display()
            ),
        )
        .unwrap();
        assert_eq!(
            unit_named_sources(&tu),
            vec![real_path(&dir.path().join("a.c"))]
        );
    }

    #[test]
    fn a_build_tree_include_dir_outside_the_project_is_generated() {
        let project = tempfile::tempdir().unwrap();
        let build = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(build.path().join("gen")).unwrap();
        std::fs::write(build.path().join("gen/config_gen.h"), "#define N 1\n").unwrap();
        std::fs::create_dir_all(project.path().join("include")).unwrap();
        let db = CompileDb {
            include_paths: vec![
                project
                    .path()
                    .join("include")
                    .to_string_lossy()
                    .into_owned(),
                build.path().join("gen").to_string_lossy().into_owned(),
            ],
            build_trees: vec![build.path().to_string_lossy().into_owned()],
            ..Default::default()
        };
        let roots = vec![project.path().to_string_lossy().into_owned()];
        let found = GeneratedHeaders::recognise(&[], Some(&db), &roots)
            .unwrap()
            .unwrap();
        assert_eq!(found.files.len(), 1);
        assert!(found
            .files
            .contains(&canonical(&build.path().join("gen/config_gen.h"))));
    }

    #[test]
    fn a_copy_of_a_project_header_is_not_generated() {
        let project = tempfile::tempdir().unwrap();
        let build = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(project.path().join("include")).unwrap();
        std::fs::write(project.path().join("include/api.h"), "int api(void);\n").unwrap();
        std::fs::create_dir_all(build.path().join("out")).unwrap();
        std::fs::write(build.path().join("out/api.h"), "int api(void);\n").unwrap();
        std::fs::write(build.path().join("out/gen.h"), "#define N 1\n").unwrap();
        let roots = vec![project.path().to_string_lossy().into_owned()];
        let declared = vec![build.path().join("out").to_string_lossy().into_owned()];
        let found = GeneratedHeaders::recognise(&declared, None, &roots)
            .unwrap()
            .unwrap();
        assert_eq!(
            found.files.iter().cloned().collect::<Vec<_>>(),
            vec![canonical(&build.path().join("out/gen.h"))]
        );
    }

    #[test]
    fn an_in_source_build_declares_nothing_by_itself() {
        // An entry compiling a file inside its own directory declares no
        // build tree: its include directories are never generated by R2.
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(project.path().join("include")).unwrap();
        std::fs::write(project.path().join("include/x.h"), "int x;\n").unwrap();
        let db = CompileDb {
            include_paths: vec![project
                .path()
                .join("include")
                .to_string_lossy()
                .into_owned()],
            build_trees: vec![],
            ..Default::default()
        };
        let roots = vec![project.path().to_string_lossy().into_owned()];
        assert!(GeneratedHeaders::recognise(&[], Some(&db), &roots)
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_declared_directory_inside_the_project_is_refused() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(project.path().join("build")).unwrap();
        let roots = vec![project.path().to_string_lossy().into_owned()];
        let declared = vec![project.path().join("build").to_string_lossy().into_owned()];
        assert!(GeneratedHeaders::recognise(&declared, None, &roots).is_err());
    }
}
