use super::function_summary::FunctionSummary;
use super::macro_expand::FunctionMacro;
use super::null_state::NullState;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

/// Marks an `include_edges` entry as an `#include` spelling that resolved to
/// no file, rather than a file's real path.
pub const UNRESOLVED_INCLUDE: &str = "?";

/// An `include_edges` entry for a computed `#include` (`#include DEFS_H`):
/// the file may include any header.
pub const ANY_INCLUDE: &str = "?*";

/// `macro_aliases` and `macro_alias_alternatives` as one file sees them
/// ([`ProjectContext::as_seen_from`]).
type AliasTables = (HashMap<String, String>, HashMap<String, Vec<String>>);

/// How an `#include` names its header.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum IncludeForm {
    /// `#include "name.h"`.
    Quoted,
    /// `#include <name.h>`.
    Angle,
    /// `#include MACRO`: the spelling is the macro, whose value the scan
    /// does not know.
    Computed,
}

/// One `#include` that resolved to no file ([`IncludeReport::unresolved`]).
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct UnresolvedInclude {
    /// The spelling, delimiters stripped.
    pub spelling: String,
    /// How the directive names it.
    pub form: IncludeForm,
    /// Real path of the file whose directive it is; empty for a forced
    /// include, which no file names.
    pub includer: String,
    /// 1-based line of the directive; 0 for a forced include.
    pub line: usize,
    /// The directive sits in an arm its own file proves is never compiled
    /// (ADR-0010 D2): counted, never headlined.
    pub in_dead_arm: bool,
    /// The includer lies outside every project root: a system header's own
    /// include, often a platform arm (`ares.h`'s NetWare `<sys/bsdskt.h>`).
    pub includer_outside_project: bool,
    /// Classified as a missing project header, presumably generated at build
    /// time (`ProjectContext::unresolved_project_headers`).
    pub project_header: bool,
}

/// What the scan's `#include` resolution could and could not see: the facts
/// that make a scan's findings depend on the host it ran on. Built by
/// `prescan::resolve_includes`, sorted, so two hosts' reports diff straight
/// to the cause. Reports only: nothing here changes a finding.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IncludeReport {
    /// The header search path in order (`-I`, compile database, system
    /// directories). A quoted or computed include is looked up in its
    /// includer's directory first.
    pub search_paths: Vec<String>,
    /// Forced includes (cl's `/FI`, `-include`), in command-line order.
    pub forced_includes: Vec<String>,
    /// Every distinct unresolved `#include`, sorted.
    pub unresolved: Vec<UnresolvedInclude>,
    /// Real paths of the headers read from outside every project root,
    /// sorted: the system headers whose declarations and macros the scan
    /// folded in.
    pub outside_headers: Vec<String>,
}

/// Whether an `#include` spelling names a header that lives in the
/// compiler's built-in directory or the multiarch directory rather than in
/// `/usr/include` itself: a fixed list of well-known spellings, the
/// `bits/`, `gnu/` and `asm/` trees and the freestanding headers the C
/// library leaves to the compiler (`stddef.h`, `stdarg.h`, ...; not
/// `limits.h` or `stdint.h`, which glibc ships in `/usr/include`). The scan
/// searches those directories only with `--system-includes`, so without it
/// they are missing on nearly every host; counting them apart keeps the
/// project's own missing headers visible. A name match only:
/// [`UnresolvedInclude::from_compiler_directory`] keeps a project's own.
pub fn in_compiler_directory(spelling: &str) -> bool {
    const TREES: &[&str] = &["bits/", "gnu/", "asm/"];
    const FREESTANDING: &[&str] = &[
        "float.h",
        "iso646.h",
        "stdalign.h",
        "stdarg.h",
        "stdatomic.h",
        "stdbool.h",
        "stddef.h",
        "stdnoreturn.h",
        "varargs.h",
    ];
    TREES.iter().any(|tree| spelling.starts_with(tree)) || FREESTANDING.contains(&spelling)
}

impl UnresolvedInclude {
    /// Whether this miss is one of the compiler's built-in or multiarch
    /// headers ([`in_compiler_directory`]), and not a missing project header
    /// that happens to share the name (a generated `asm/...`).
    pub fn from_compiler_directory(&self) -> bool {
        !self.project_header && in_compiler_directory(&self.spelling)
    }
}

impl IncludeReport {
    /// The unresolved includes in code some configuration compiles.
    pub fn live(&self) -> impl Iterator<Item = &UnresolvedInclude> {
        self.unresolved.iter().filter(|u| !u.in_dead_arm)
    }

    /// The one-line stderr summary, or `None` when every live `#include`
    /// resolved. Distinct spellings are counted, so a header missing from
    /// fifty files reads as one missing header. Headers that live in the
    /// compiler's built-in or multiarch directories
    /// ([`in_compiler_directory`]), which the scan searches only with
    /// `--system-includes`, are counted apart and never headlined: without
    /// that flag nearly every scan misses them, so they would drown out the
    /// project's own missing headers.
    pub fn summary_line(&self) -> Option<String> {
        let live: Vec<&UnresolvedInclude> = self.live().collect();
        if live.is_empty() {
            return None;
        }
        fn distinct<'a>(
            rows: &mut dyn Iterator<Item = &&'a UnresolvedInclude>,
        ) -> std::collections::BTreeSet<&'a str> {
            rows.map(|u| u.spelling.as_str()).collect()
        }
        let (compiler, rest): (Vec<&UnresolvedInclude>, Vec<&UnresolvedInclude>) =
            live.into_iter().partition(|u| u.from_compiler_directory());
        let compiler = distinct(&mut compiler.iter());
        let compiler_examples = || {
            let more = if compiler.len() > 3 { ", ..." } else { "" };
            let names: Vec<&str> = compiler.iter().copied().take(3).collect();
            format!("{}{more}", names.join(", "))
        };
        if rest.is_empty() {
            return Some(format!(
                "Headers: {} #include'd header(s) not found, all from the compiler's built-in \
                 and multiarch directories, which the scan searches only with \
                 --system-includes: {}. -v lists each, --report-headers FILE writes them all.",
                compiler.len(),
                compiler_examples()
            ));
        }
        let all = distinct(&mut rest.iter()).len();
        let in_project = distinct(&mut rest.iter().filter(|u| !u.includer_outside_project)).len();
        // A spelling some project file names counts there, not here too.
        let named_by_project = distinct(&mut rest.iter().filter(|u| !u.includer_outside_project));
        let in_system = distinct(&mut rest.iter().filter(|u| u.includer_outside_project))
            .difference(&named_by_project)
            .count();
        let mut examples: Vec<&str> =
            distinct(&mut rest.iter().filter(|u| !u.includer_outside_project))
                .into_iter()
                .take(3)
                .collect();
        if examples.is_empty() {
            examples = distinct(&mut rest.iter()).into_iter().take(3).collect();
        }
        let more = if all > examples.len() { ", ..." } else { "" };
        let apart = if compiler.is_empty() {
            String::new()
        } else {
            format!(
                " Not counted: {} from the compiler's built-in and multiarch directories, \
                 which the scan searches only with --system-includes ({}).",
                compiler.len(),
                compiler_examples()
            )
        };
        Some(format!(
            "Headers: {all} #include'd header(s) not found ({in_project} named by project files, \
             {in_system} only by system headers): {}{more}. Declarations and macros they would \
             supply were not seen, so findings that depend on them can differ from a host that \
             has them; -v lists each, --report-headers FILE writes them all.{apart}",
            examples.join(", ")
        ))
    }

    /// The `--report-headers` JSON: this report, each outside header given
    /// with the SHA-256 of its bytes so "same header, different version"
    /// shows up as a diff line (unreadable now: `null`).
    pub fn to_json_with_hashes(&self) -> serde_json::Value {
        use sha2::{Digest, Sha256};
        let outside: Vec<serde_json::Value> = self
            .outside_headers
            .iter()
            .map(|path| {
                let sha256 = std::fs::read(path)
                    .ok()
                    .map(|bytes| format!("{:x}", Sha256::digest(bytes)));
                serde_json::json!({ "path": path, "sha256": sha256 })
            })
            .collect();
        serde_json::json!({
            "search_paths": self.search_paths,
            "forced_includes": self.forced_includes,
            "unresolved": self.unresolved,
            "outside_headers": outside,
        })
    }

    /// The `-v` listing: the search path once, then one line per live
    /// unresolved `#include`, then the dead-arm count.
    pub fn render_verbose(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let live: Vec<&UnresolvedInclude> = self.live().collect();
        if live.is_empty() {
            return out;
        }
        let _ = writeln!(
            out,
            "Header search path (after the includer's own directory for \"...\" and computed \
             includes): {}",
            if self.search_paths.is_empty() {
                "(none)".to_string()
            } else {
                self.search_paths.join(", ")
            }
        );
        for u in live {
            let (open, close) = match u.form {
                IncludeForm::Quoted => ("\"", "\""),
                IncludeForm::Angle => ("<", ">"),
                IncludeForm::Computed => ("", ""),
            };
            let from = if u.includer.is_empty() {
                "forced include".to_string()
            } else {
                format!("{}:{}", u.includer, u.line)
            };
            let what = match (u.includer_outside_project, u.project_header) {
                (true, _) => "named by a system header",
                (false, true) => "project header, presumably generated at build time",
                (false, false) => "named by a project file",
            };
            let compiler = if u.from_compiler_directory() {
                " (compiler built-in or multiarch directory: --system-includes searches it)"
            } else {
                ""
            };
            let computed = if u.form == IncludeForm::Computed {
                " (computed: the macro's value is unknown)"
            } else {
                ""
            };
            let _ = writeln!(
                out,
                "unresolved #include {open}{}{close} from {from}: {what}{computed}{compiler}",
                u.spelling
            );
        }
        let dead = self.unresolved.len() - self.live().count();
        if dead > 0 {
            let _ = writeln!(
                out,
                "({dead} more in arms their own file proves are never compiled)"
            );
        }
        out
    }
}

/// Which findings may depend on a header the scan could not find: those of a
/// rule that reads header-supplied facts (`CertRule::reads_header_facts`) in
/// a file whose include graph reaches a live `#include` that resolved to no
/// file. "May": the rule could have needed something that header would have
/// supplied, not proof that it did. It turns "is this finding header-driven?"
/// into a grep over two hosts' exports instead of an A/B.
#[derive(Debug, Default, Clone)]
pub struct HeaderDependence {
    /// The enabled rules that read header-supplied facts.
    pub rules: std::collections::BTreeSet<String>,
    /// A finding's `file_path` -> the missing headers (spellings, sorted)
    /// its include graph reaches; only files with such a finding.
    pub by_file: BTreeMap<String, Arc<[String]>>,
    /// A finding's (`file_path`, line) -> the macros spelled on that line
    /// that only headers outside the project define, each as
    /// `NAME (header path)`, sorted: where a finding that relies on one got
    /// it (tomcrypt_custom.h's `XFREE` standing in for wolfSSL's). By line,
    /// so a macro spelled elsewhere is missed ([`Self::build`]).
    pub harvested: BTreeMap<(String, usize), Arc<[String]>>,
}

impl HeaderDependence {
    /// The missing headers the finding of `rule_id` in `file_path` may
    /// depend on, or `None`.
    pub fn of(&self, rule_id: &str, file_path: &str) -> Option<&[String]> {
        if !self.rules.contains(rule_id) {
            return None;
        }
        self.by_file.get(file_path).map(|headers| &headers[..])
    }

    /// The outside-header macros on the line of the finding of `rule_id` at
    /// `file_path`:`line`, or `None`.
    pub fn harvested_at(&self, rule_id: &str, file_path: &str, line: usize) -> Option<&[String]> {
        if !self.rules.contains(rule_id) {
            return None;
        }
        self.harvested
            .get(&(file_path.to_string(), line))
            .map(|macros| &macros[..])
    }

    /// Build it for `files` (the `file_path`s of the findings of `rules`):
    /// for each, the live unresolved `#include`s that a project file in its
    /// include closure ([`IncludeClosure::of_layers`] over `layers`:
    /// `include_edges` and `include_edges_beyond_search_path`) names, or
    /// that the file itself or a forced include names when the graph has no
    /// edge out of it; an unresolved forced include counts for every file.
    /// The compiler's built-in and multiarch headers
    /// ([`UnresolvedInclude::from_compiler_directory`]) don't count.
    ///
    /// And for each finding's line, the macros spelled on it that
    /// `outside_macros` (`ProjectContext::outside_macro_origins`) says only
    /// headers outside the project define. The file is read once. This goes
    /// by the finding's line, not by what the rule used: a macro the finding
    /// relies on but that is spelled on another line (at a declaration, or
    /// inside another macro's body) is not named, and a macro on the line
    /// that the rule never looked at is, as is a name inside a comment or a
    /// string on the line.
    pub fn build<'a>(
        rules: std::collections::BTreeSet<String>,
        findings: impl IntoIterator<Item = (&'a str, usize)>,
        report: &IncludeReport,
        layers: &[&HashMap<String, Vec<String>>],
        outside_macros: &BTreeMap<String, Vec<String>>,
    ) -> Self {
        let findings: Vec<(&str, usize)> = findings.into_iter().collect();
        let files = findings.iter().map(|&(file, _)| file);
        let harvested = Self::harvested(&findings, outside_macros);
        let mut by_file = BTreeMap::new();
        let mut live: HashMap<&str, Vec<&str>> = HashMap::new();
        // Only includes a project file names: a header missing only from a
        // system header's own includes (`bits/*` from libc's headers) is
        // missing on nearly every host and says nothing about this finding,
        // so it stays in `-v` and `--report-headers`. So do the compiler's
        // built-in and multiarch headers, for the same reason.
        for u in report
            .live()
            .filter(|u| !u.includer_outside_project && !u.from_compiler_directory())
        {
            live.entry(u.includer.as_str())
                .or_default()
                .push(&u.spelling);
        }
        if !live.is_empty() && !rules.is_empty() {
            // Every translation unit sees the forced includes; a closure
            // walks them already, a file with no edge out of it doesn't.
            let forced: Vec<String> = IncludeClosure::of_forced_includes(layers)
                .map(|closure| closure.files.into_iter().collect())
                .unwrap_or_default();
            for file in files {
                if by_file.contains_key(file) {
                    continue;
                }
                let path = Path::new(file);
                let mut reached: Vec<String> = match IncludeClosure::of_layers(layers, path) {
                    Some(closure) => closure.files.into_iter().collect(),
                    None => {
                        let mut alone = vec![crate::analyze::compile_commands::real_path(path)];
                        alone.extend(forced.iter().cloned());
                        alone
                    }
                };
                // A forced include that resolved to no file is filed under
                // the empty includer.
                reached.push(String::new());
                let missing: std::collections::BTreeSet<&str> = reached
                    .iter()
                    .filter_map(|f| live.get(f.as_str()))
                    .flatten()
                    .copied()
                    .collect();
                if !missing.is_empty() {
                    let missing: Vec<String> = missing.into_iter().map(String::from).collect();
                    by_file.insert(file.to_string(), Arc::from(missing));
                }
            }
        }
        Self {
            rules,
            by_file,
            harvested,
        }
    }

    fn harvested(
        findings: &[(&str, usize)],
        outside_macros: &BTreeMap<String, Vec<String>>,
    ) -> BTreeMap<(String, usize), Arc<[String]>> {
        let mut out = BTreeMap::new();
        if outside_macros.is_empty() {
            return out;
        }
        let mut sources: HashMap<&str, Option<String>> = HashMap::new();
        for &(file, line) in findings {
            if out.contains_key(&(file.to_string(), line)) {
                continue;
            }
            let source = sources
                .entry(file)
                .or_insert_with(|| std::fs::read_to_string(file).ok());
            let Some(text) = source
                .as_deref()
                .and_then(|s| s.lines().nth(line.checked_sub(1)?))
            else {
                continue;
            };
            let names: std::collections::BTreeSet<&str> = text
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .filter(|w| w.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'))
                .collect();
            let macros: Vec<String> = names
                .into_iter()
                .filter_map(|name| {
                    let paths = outside_macros.get(name)?;
                    Some(format!("{name} ({})", paths.join(", ")))
                })
                .collect();
            if !macros.is_empty() {
                out.insert((file.to_string(), line), Arc::from(macros));
            }
        }
        out
    }
}

/// What one translation unit may include: [`IncludeClosure::of`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IncludeClosure {
    /// Real paths of the file and every header it transitively includes.
    pub files: HashSet<String>,
    /// Spellings of the includes along the way that resolved to no file
    /// (`/`-separated, `.` and `..` segments dropped), each of which may name
    /// a header the prescan read under some other search path.
    pub unresolved: HashSet<String>,
    /// Whether a computed `#include` along the way may name any header.
    pub any: bool,
}

impl IncludeClosure {
    /// The file at `path`, the build's forced includes and everything those
    /// transitively `#include`, by `edges` ([`ProjectContext::include_edges`]);
    /// `None` when the graph has no edge out of the file, so which files it
    /// sees is unknown.
    pub fn of(edges: &HashMap<String, Vec<String>>, path: &Path) -> Option<Self> {
        Self::of_layers(&[edges], path)
    }

    /// [`IncludeClosure::of`] over the union of several edge maps: an edge in
    /// any layer counts. `None` when no layer has an edge out of the file.
    pub fn of_layers(layers: &[&HashMap<String, Vec<String>>], path: &Path) -> Option<Self> {
        let file = crate::analyze::compile_commands::real_path(path);
        if !layers.iter().any(|edges| edges.contains_key(&file)) {
            return None;
        }
        let mut closure = Self::default();
        closure.files.insert(file.clone());
        closure.walk(layers, vec![file, String::new()]);
        Some(closure)
    }

    /// What every translation unit includes regardless of its own
    /// `#include` lines: the build's forced includes (filed under the empty
    /// name) and everything they include. `None` when there are none.
    pub fn of_forced_includes(layers: &[&HashMap<String, Vec<String>>]) -> Option<Self> {
        if !layers.iter().any(|edges| edges.contains_key("")) {
            return None;
        }
        let mut closure = Self::default();
        closure.walk(layers, vec![String::new()]);
        Some(closure)
    }

    fn walk(&mut self, layers: &[&HashMap<String, Vec<String>>], mut stack: Vec<String>) {
        let closure = self;
        while let Some(f) = stack.pop() {
            for next in layers.iter().filter_map(|edges| edges.get(&f)).flatten() {
                if next == ANY_INCLUDE {
                    closure.any = true;
                } else if let Some(spelling) = next.strip_prefix(UNRESOLVED_INCLUDE) {
                    // `../common/defs.h` names some `common/defs.h`: the
                    // directory it climbs to is the includer's, not a part
                    // of the header's own path.
                    let spelling = spelling
                        .split(['/', '\\'])
                        .filter(|segment| !matches!(*segment, "" | "." | ".."))
                        .collect::<Vec<_>>()
                        .join("/");
                    if !spelling.is_empty() {
                        closure.unresolved.insert(spelling);
                    }
                } else if closure.files.insert(next.clone()) {
                    stack.push(next.clone());
                }
            }
        }
    }

    /// Whether the translation unit may include the file at real path
    /// `file`: it is in the closure, or an unresolved include spells a path
    /// the file ends with.
    pub fn may_include(&self, file: &str) -> bool {
        self.any
            || self.files.contains(file)
            || self.unresolved.iter().any(|spelling| {
                file.strip_suffix(spelling.as_str())
                    .is_some_and(|dir| dir.ends_with('/'))
            })
    }
}

impl ProjectContext {
    /// The [`unresolved_project_headers`](Self::unresolved_project_headers)
    /// the file at `path` may include, sorted: those its include closure
    /// ([`IncludeClosure::of`]) names, or all of them when a computed
    /// `#include` along the way may name any header. Empty when the file's
    /// closure is unknown (it has no include edge, so it names no header).
    pub fn unresolved_project_headers_reached(&self, path: &Path) -> Vec<String> {
        unresolved_project_headers_reached(
            &self.include_edges,
            &self.include_edges_beyond_search_path,
            &self.unresolved_project_headers,
            path,
        )
    }
}

/// [`ProjectContext::unresolved_project_headers_reached`] for a holder of just
/// the tables it reads.
pub fn unresolved_project_headers_reached(
    include_edges: &HashMap<String, Vec<String>>,
    include_edges_beyond_search_path: &HashMap<String, Vec<String>>,
    unresolved_project_headers: &HashSet<String>,
    path: &Path,
) -> Vec<String> {
    if unresolved_project_headers.is_empty() {
        return Vec::new();
    }
    let layers = [include_edges, include_edges_beyond_search_path];
    // A file with no #include of its own has no edge, but the build's forced
    // includes (`-include gen.h`) still reach it.
    let Some(closure) = IncludeClosure::of_layers(&layers, path)
        .or_else(|| IncludeClosure::of_forced_includes(&layers))
    else {
        return Vec::new();
    };
    // The closure records spellings with `.` and `..` segments dropped.
    let normalized = |spelling: &str| {
        spelling
            .split(['/', '\\'])
            .filter(|segment| !matches!(*segment, "" | "." | ".."))
            .collect::<Vec<_>>()
            .join("/")
    };
    let mut reached: Vec<String> = unresolved_project_headers
        .iter()
        .filter(|header| closure.any || closure.unresolved.contains(&normalized(header)))
        .cloned()
        .collect();
    reached.sort_unstable();
    reached
}

/// Cross-file context gathered by pre-scanning additional directories.
///
/// Holds function names found in `.c`/`.h` files so that rules like DCL31-C
/// and DCL07-C can suppress false positives for project-internal functions
/// defined in other translation units.
///
/// The tables are `Arc`-wrapped because every scanned file hands this context
/// to a fresh set of rule instances, each of which keeps its own handle
/// (`set_project_context`). A handle is a refcount bump; a deep copy of the
/// function summaries of a few-thousand-file project, per rule, per file, was
/// the dominant cost of a scan. Build the tables in full, then wrap; after
/// that, mutate only through `Arc::make_mut` and only before rules see the
/// context (`resolve_includes`, the compile-database merge).
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProjectContext {
    /// Files whose prescan crashed or ran out of budget
    /// (`containment::Stage::Prescan`): their cross-file facts are missing,
    /// so findings anywhere may differ from a complete scan's. Never
    /// serialized -- a context with failures is not saved as a cache at
    /// all (`analyze::load_project_context`), so no later scan can inherit
    /// the gap silently.
    #[serde(skip)]
    pub prescan_failures: Vec<crate::analyze::containment::ScanFailure>,
    /// The policy and environment settings this run analyzes under.
    ///
    /// Never serialized: a prescan records facts about the code (which
    /// functions are declared `_Noreturn`, which are verified never to
    /// return), and the settings decide what a rule may conclude from them.
    /// A cache saved under one setting is therefore valid under every other,
    /// and must stay so -- a table that bakes a setting in must record it in
    /// [`built_under`](Self::built_under).
    #[serde(skip)]
    pub settings: Arc<crate::settings::AnalysisSettings>,
    /// The settings the collected facts themselves depend on, by name and
    /// value, such as `include_names`: which headers were found at all
    /// depends on it. `prescan_scope` names the path globs whose files the
    /// prescan did not read (`--exclude-all`, `--prescan-exclude` and their
    /// manifest keys), as a sorted JSON list, or "" for none: a context built
    /// without some files holds other definitions. Recorded when the context
    /// is built; a cache loaded under a different value for any of them is
    /// refused ([`check_built_under`](Self::check_built_under)) rather than
    /// silently mixing two scans.
    ///
    /// `#[serde(default)]` does not make an older cache readable: bincode
    /// reads fields by position, so the cache format header is what refuses
    /// a cache from before this field existed.
    #[serde(default)]
    pub built_under: BTreeMap<String, String>,
    /// The allocator and deallocator declarations the function summaries
    /// were built under (`settings::memory`). Unlike the settings above this
    /// IS baked into the tables -- a wrapper around a declared hook frees by
    /// its summary -- so the cache records it and a run under different
    /// declarations refuses the cache. It is its own field, compared whole,
    /// rather than a `built_under` key, where a key absent from either side
    /// would read as not compared.
    pub memory_declarations: crate::settings::MemoryDeclarations,
    /// Every function name found in the pre-scanned `.c`/`.h` files.
    pub known_functions: Arc<HashSet<String>>,
    /// Functions declared (prototyped) in `.h` header files.
    /// A function with a header prototype is public API and should not be
    /// flagged by DCL15-C/DCL19-C as needing `static`.
    pub header_declared_functions: Arc<HashSet<String>>,
    /// Function summaries computed during prescan for inter-procedural analysis.
    pub function_summaries: ScopedTable<FunctionSummary>,
    /// Call graph: maps function name to the set of functions it calls.
    pub call_graph: Arc<HashMap<String, HashSet<String>>>,
    /// The inverse of `call_graph`: maps a function name to the set of
    /// functions that call it. Computed once when the context is built, so
    /// a rule asking "who calls this?" per file does not re-invert the whole
    /// graph per file (six rules did, each on every file).
    #[serde(default)]
    pub callers: Arc<HashMap<String, HashSet<String>>>,
    /// Callee names that must never be resolved to a same-named function
    /// definition by name matching alone: names reached only through a
    /// `field_expression` call (`obj->cb(...)`) or through a plain
    /// identifier that is also a parameter name of the calling function
    /// (a callback passed by the caller, shadowing any same-named global
    /// function per C scoping rules). `call_graph` may still contain edges
    /// to these names (recorded by the underlying, name-matching-only call
    /// graph builder), so a consumer doing cycle/reachability analysis
    /// through unresolved indirect calls should treat any callee in this
    /// set as opaque rather than chase it.
    #[serde(default)]
    pub ambiguous_call_targets: Arc<HashSet<String>>,
    /// Macro constants collected from `#define` directives across all scanned files.
    pub macro_constants: Arc<HashMap<String, i64>>,
    /// Macro aliases: `#define ALIAS identifier` patterns (e.g., `SYSTEM` → `system`).
    /// Used by rules to resolve function calls through macro indirection.
    pub macro_aliases: Arc<HashMap<String, String>>,
    /// Every live target of each `#define ALIAS identifier` across the
    /// scanned files; `macro_aliases` holds only the names with one target.
    /// Read through `const_eval::resolve_macro_alias_where` by a rule the
    /// alias accuses through.
    #[serde(default)]
    pub macro_alias_alternatives: Arc<HashMap<String, Vec<String>>>,
    /// The argument counts each function or function-like macro the
    /// scanned files and resolved headers define or prototype takes
    /// (`const_eval::fixed_arities`), one entry per distinct arity.
    #[serde(default)]
    pub function_arities: Arc<HashMap<String, Vec<crate::analyze::const_eval::Arity>>>,
    /// `file -> name -> the argument counts the file calls it with`, real
    /// paths, for the names some alias defines (`const_eval::call_arities`).
    /// An alias whose target cannot take a count a file calls it with is not
    /// the definition in force in that file: [`Self::as_seen_from`].
    #[serde(default)]
    pub alias_call_arities: Arc<HashMap<String, HashMap<String, Vec<usize>>>>,
    /// Struct field types: maps `struct_name -> field_name -> type_text`.
    /// Enables resolving types of `field_expression` nodes (e.g., `s->count` → "int").
    pub struct_field_types: Arc<HashMap<String, HashMap<String, String>>>,
    /// Names of struct (and typedef-aliased) types declared
    /// `__attribute__((packed))` (directly or via a macro like
    /// `STRUCT_PACKED` whose `#define` expands to packed) across all scanned
    /// files, incl. headers. A packed struct's actual alignment is 1, so
    /// EXP36-C must not treat a cast into it as alignment-increasing.
    #[serde(default)]
    pub packed_structs: Arc<HashSet<String>>,
    /// Functions some scanned file registers as a signal handler
    /// (`signal`/`sigaction`, directly or through its own wrapper) without
    /// defining them there, and some scanned file or header declares
    /// (`known_functions`: a prototype or definition, and function-like macro
    /// names too). SIG34-C acts only on a `function_definition`, and judges
    /// a definition of one as a handler in the file that defines it,
    /// unless that definition is `static` (then it is not the function the
    /// other file names).
    #[serde(default)]
    pub signal_handlers_registered_elsewhere: Arc<HashSet<String>>,
    /// Names of functions known never to return to their caller, collected
    /// across all scanned files (incl. headers) by
    /// [`crate::analyze::noreturn::collect_noreturn_names`]: the fixed C
    /// standard library set, `_Noreturn` qualifiers, and definitions
    /// verified never to return -- once per combination of
    /// `trust_noreturn_keyword` and `stdlib_noreturn`; a reader picks one with
    /// [`ByNoreturnTrust::get`](crate::analyze::noreturn::ByNoreturnTrust::get).
    /// Cross-file because the declaration carrying the keyword is routinely
    /// in a header the single-file parse never sees.
    #[serde(default)]
    pub noreturn_functions: crate::analyze::noreturn::ByNoreturnTrust<Arc<HashSet<String>>>,
    /// `noreturn_functions` plus every `.c` file's own `static` noreturn
    /// names, which `noreturn_functions` leaves to the file that defines
    /// them. The input [`abort_check_macros`](Self::abort_check_macros) is
    /// built from, at both of its build sites: that table is project-wide and
    /// keyed by macro name, so a file-local check macro calling its file's
    /// static exit helper must still qualify.
    #[serde(default)]
    pub abort_check_noreturn_functions:
        crate::analyze::noreturn::ByNoreturnTrust<Arc<HashSet<String>>>,
    /// Global constants: `[const] TYPE NAME = VALUE;` from across all scanned files.
    /// Used by init-state analysis for dead-branch elimination.
    #[serde(default)]
    pub global_constants: HashMap<String, i64>,
    /// The names in `global_constants` that are constants only in a closed
    /// program (the `closed_program` setting): a non-`const` global with
    /// external linkage, or a non-static function that returns a literal.
    /// Outside a closed program another translation unit may write the one
    /// or interpose the other (ADR-0011).
    #[serde(default)]
    pub closure_dependent_constants: Arc<HashSet<String>>,
    /// Global pointer variable null states from across all scanned files.
    /// Maps variable name to its joined null state across all assignment sites.
    /// Used by EXP34-C to resolve `extern` pointer globals declared in other
    /// translation units (Juliet CWE-476 variant 68 pattern).
    #[serde(default)]
    pub global_var_null_states: Arc<HashMap<String, NullState>>,
    /// File-scope `static` variable writers: maps static-variable name to the
    /// set of function names that assign to it. Used by ENV03-C (and other
    /// taint-aware rules) to decide whether a `char *data = g_static;` read
    /// brings in taint — if every writer's summary is taint-free, the global
    /// is treated as clean. Targets Juliet CWE-78 variant 45 (goodG2BSink
    /// pattern).
    #[serde(default)]
    pub global_writers: Arc<HashMap<String, HashSet<String>>>,
    /// Function-like macro definitions (`#define NAME(a,b) body`) collected
    /// across all scanned files (incl. headers) during the prescan pre-pass.
    /// Consumed by `macro_expand` to expand opaque macro invocations on demand
    /// (Phase 2 of docs/design/macro-expansion.md). Macros using `#`/`##` or
    /// variadics are intentionally excluded (see `macro_expand`).
    #[serde(default)]
    pub function_macros: Arc<HashMap<String, FunctionMacro>>,
    /// Every `#define` of every name across all scanned files (incl.
    /// headers), in every preprocessor arm the file does not itself prove
    /// dead, each distinct definition kept. Raw material for
    /// [`abort_check_macros`](Self::abort_check_macros), which must see every
    /// alternative, not the one `function_macros` keeps.
    #[serde(default)]
    pub macro_definitions: Arc<HashMap<String, Vec<crate::analyze::check_macros::MacroDefinition>>>,
    /// Names `#define`d in a header resolved from outside every project root
    /// (a system header: glibc's `#define signal __sysv_signal`) and in no
    /// scanned file or project header. The project roots are the scanned
    /// tree and every `-d` directory; a single-file target's root is the
    /// directory holding it. Their `macro_definitions` are the
    /// implementation's, not the project's: a rule judging a call by what a
    /// macro expands to can still say so in the name the code wrote.
    #[serde(default)]
    pub macros_defined_outside_project: Arc<HashSet<String>>,
    /// Names `#define`d inside a live `#if`/`#ifdef`/`#ifndef` arm of any
    /// scanned file or header, per
    /// [`crate::analyze::check_macros::collect_conditional_macro_names`]: a
    /// configuration exists in which that definition is absent, so what the
    /// name expands to is not settled by `macro_definitions` alone.
    #[serde(default)]
    pub conditional_macro_names: Arc<HashSet<String>>,
    /// Constant names whose value is not fixed in every configuration, from
    /// every scanned file and header
    /// ([`crate::analyze::const_eval::config_dependent_constant_names`]):
    /// defined differently across `#if` arms, or only as an `#ifndef`
    /// default. `macro_constants` still resolves them (ADR-0010 D3); a rule
    /// treating a constant condition as proof a branch is dead leaves them
    /// out (D8).
    #[serde(default)]
    pub config_dependent_constants: Arc<HashSet<String>>,
    /// `macro name -> index of the parameter it checks`, for the assert-style
    /// macros no configuration compiles out (valkey's `serverAssert`), per
    /// [`crate::analyze::check_macros::abort_check_macros`], under each
    /// noreturn setting ([`crate::analyze::noreturn::ByNoreturnTrust`]:
    /// whether a macro's failure path
    /// ends depends on which functions count as noreturn). Recomputed
    /// whenever `macro_definitions` or `noreturn_functions` grows.
    #[serde(default)]
    pub abort_check_macros: crate::analyze::noreturn::ByNoreturnTrust<Arc<HashMap<String, usize>>>,
    /// Names of every `#define NAME ...` object-like macro collected across
    /// all scanned files (incl. headers), regardless of what they expand to.
    /// Used by DCL40-C to recognize a trailing bare identifier after a
    /// struct/union/enum body (e.g. hostap's `struct foo { ... }
    /// STRUCT_PACKED;`) as an attribute-position macro invocation rather
    /// than a genuine object declaration — the `#define` commonly lives in a
    /// different file than the struct.
    #[serde(default)]
    pub defined_macro_names: Arc<HashSet<String>>,
    /// Names of every function-like `#define` across all scanned files
    /// (incl. headers), in every preprocessor branch and including variadic
    /// and `#`/`##` macros: what says a call is a macro invocation, rather
    /// than the callee's spelling. See
    /// [`crate::analyze::macro_expand::FunctionMacroNames`].
    #[serde(default)]
    pub function_macro_names: Arc<HashSet<String>>,
    /// Names of every object-like `#define` whose replacement list contains
    /// `static` (`#define STATIC static`), across all scanned files (incl.
    /// headers), any branch. See
    /// [`crate::utility::cert_c::ast_utils::collect_static_macro_names`].
    #[serde(default)]
    pub static_macro_names: Arc<HashSet<String>>,
    /// For every function-like `#define` that applies `#` or `##` to a
    /// parameter, which parameters those are, across all scanned files
    /// (incl. headers), all branches. See
    /// [`crate::analyze::macro_expand::collect_macro_operand_params`].
    #[serde(default)]
    pub macro_operand_params: Arc<HashMap<String, crate::analyze::macro_expand::OperandParams>>,
    /// Every function-like `#define` across the scanned headers (and any .c
    /// file another file `#include`s: a `.c` file's own macros are live only
    /// in its translation unit), one entry per distinct definition: every
    /// preprocessor branch not proven dead, variadic and `#`/`##` arms
    /// included (unlike
    /// `function_macros`, which keeps one expandable definition per name).
    /// For a question about every definition a call may expand to, such as
    /// how many times it evaluates an argument. See
    /// [`crate::analyze::macro_expand::collect_function_macro_arms`].
    #[serde(default)]
    pub function_macro_arms:
        Arc<HashMap<String, Vec<crate::analyze::macro_expand::ProjectMacroArm>>>,
    /// `file -> the files its #include directives resolve to`, real paths,
    /// from `resolve_includes` (so only when there are search paths or forced
    /// includes). The build's forced includes are filed under the empty
    /// name, and an include that resolved to no file under its spelling
    /// behind [`UNRESOLVED_INCLUDE`]. [`IncludeClosure::of`] walks it.
    #[serde(default)]
    pub include_edges: Arc<HashMap<String, Vec<String>>>,
    /// The context of a file the build configuration does not compile: built
    /// from the same prescan with the build-generated headers withheld, so it
    /// is exactly the context the scan would have had if they were missing
    /// (`generated_headers`). `None` when the scan recognised none, and in
    /// itself.
    #[serde(default)]
    pub outside_configuration: Option<Arc<ProjectContext>>,
    /// Edges `include_edges` leaves out: an include this run's search path
    /// can't resolve, to the project files whose path ends in its spelling
    /// (seL4's `<arch/machine.h>` without `-I include/arch/x86`), and onward
    /// through those files' own `#include` lines. Only the include lines are
    /// read, nothing is harvested, and only
    /// [`Self::unresolved_project_headers_reached`] walks it, so no rule sees
    /// a declaration or a closure it didn't before. Several matches (one per
    /// architecture) are all recorded, so a file counts as reaching a
    /// generated header if any of them does.
    #[serde(default)]
    pub include_edges_beyond_search_path: Arc<HashMap<String, Vec<String>>>,
    /// What `#include` resolution could and could not see
    /// ([`IncludeReport`]); empty when no search path was given.
    #[serde(default)]
    pub include_report: Arc<IncludeReport>,
    /// Each macro defined only outside the project (in
    /// `macros_defined_outside_project`) -> the real paths of the headers
    /// that define it, sorted: where a finding that relies on one got it.
    #[serde(default)]
    pub outside_macro_origins: Arc<BTreeMap<String, Vec<String>>>,
    /// Names of every object-like `#define` whose replacement text is an
    /// unused-attribute annotation — `__attribute__((unused))`,
    /// `[[maybe_unused]]`, and the reserved spellings — collected across all
    /// scanned files (incl. headers). seL4's `UNUSED`, hostap's
    /// `STRUCT_PACKED`-adjacent annotations and the rest are recognized by
    /// what they *expand to*, never by name, and the `#define` almost always
    /// lives in a different file from the declaration it annotates.
    ///
    /// Used by MSC13-C: aurora-lint has no preprocessor, so such a macro sits
    /// in the declaration where a type or declarator is expected and the
    /// recovered parse misnames the variable. The annotation is the author
    /// stating the variable may legitimately go unused, which is exactly
    /// what MSC13-C exists to respect, so a declaration carrying one is not
    /// reported at all.
    #[serde(default)]
    pub unused_attribute_macros: Arc<HashSet<String>>,
    /// Functions whose name appears as a bare value inside an aggregate
    /// initializer (e.g. `{ "mysql", pw_mysql_parse, pw_mysql_check,
    /// pw_mysql_exit }` or a designated `.check = pw_mysql_check`) — the
    /// dispatch-table registration idiom used by callback-style backends
    /// (auth/log/protocol handler tables) — and that are never invoked
    /// through a direct-by-name `identifier(...)` call anywhere in the
    /// project. Such a function is reachable only through the single
    /// indirect call site that walks the table, so API00-C treats it like
    /// a project-internal helper (extending an earlier internal-contract
    /// suppression to the dispatch-table-callback shape).
    #[serde(default)]
    pub dispatch_table_callbacks: HashSet<String>,
    /// `#include` paths that name a *project* header which is not on disk:
    /// the directory prefix resolves under one of the search roots but the
    /// file itself does not exist (e.g. seL4's `<object/structures_gen.h>`,
    /// emitted at build time by `tools/bitfield_gen.py` from an `.bf` spec;
    /// likewise `*.pb-c.h`, `*.tab.h`, and other generated headers).
    ///
    /// A system header that simply isn't on the `-I` path (`<sys/socket.h>`)
    /// does *not* land here — its directory prefix doesn't exist under the
    /// project either — so this set means specifically "this project's
    /// declaration set is incomplete because a build step we can't run
    /// produces part of it". Nor does an include written inside a header
    /// outside every project root (a system header's own missing includes),
    /// or one in an arm its file proves is never compiled (ADR-0010 D2).
    /// A rule stands down only in the files that may include one of these
    /// ([`Self::unresolved_project_headers_reached`]), and reports where
    /// through `CertRule::stand_down_report`.
    #[serde(default)]
    pub unresolved_project_headers: HashSet<String>,
    /// Every place the macro-expansion engine declined or failed to see a
    /// definition while building this context — skipped variadic / `#`/`##`
    /// macros, platform-dead and ambiguous definitions, cross-file conflicts,
    /// unresolvable `#include`s. Recorded unconditionally (it is a by-product
    /// of scans that already run) and surfaced only by `--report-macro-gaps`;
    /// nothing in analysis reads it.
    #[serde(default)]
    pub macro_gaps: Vec<super::macro_gaps::MacroGap>,
    /// `function name -> indices of its restrict-qualified parameters`, for
    /// every function any scanned file defines or declares with at least one.
    /// First definition seen wins. Lets EXP43-C confine its aliasing check
    /// to callees whose contract actually forbids aliasing.
    #[serde(default)]
    pub restrict_params: HashMap<String, Vec<usize>>,
    /// Function names reachable (including the root itself) from a real
    /// concurrent-execution root: an ISR handler, a thread-spawn entry
    /// point (`pthread_create`/`thrd_create`/`CreateThread`, direct or
    /// forwarded through a function-like macro), or a `signal()`-registered
    /// handler. Computed once during prescan by forward-walking
    /// `call_graph` from every detected root (`ambiguous_call_targets`
    /// edges excluded — see that field's docs). Empty when the scanned
    /// project has no such root anywhere (e.g. a genuinely single-threaded
    /// codebase). Used by CON03-C/CON07-C to gate findings on whether the
    /// flagged code is ever reachable from a concurrent context at all,
    /// rather than firing unconditionally (see
    /// `docs/design/con03-con07-isr-thread-reachability.md`).
    #[serde(default)]
    pub concurrency_reachable: Arc<HashSet<String>>,
    /// Names of project-wide (file-scope, non-local) variables declared with
    /// a plain, non-pointer/non-array/non-function type -- across every
    /// scanned `.c` AND `.h` file, extern declarations included, since the
    /// `extern` forward-declaration and the actual definition are typically
    /// in different files. A name is excluded if it is ever declared with a
    /// pointer or array declarator anywhere in the project (conservative:
    /// only one true global object can exist per name at link time, so
    /// disagreement means something this heuristic shouldn't guess about).
    ///
    /// Mirrors MEM31-C's per-function `value_only_locals`
    /// (`collect_value_only_locals`) but at project scope: seL4's
    /// `current_lookup_fault`/`current_fault` globals are `extern`-declared
    /// in a header and assigned via a bitfield-generator `_new()` value
    /// constructor (`current_lookup_fault = lookup_fault_new(...)`) from
    /// several other translation units, with no local declaration in any of
    /// them -- MEM31-C's per-function pointer-evidence guard can't see a
    /// declaration at all in that shape, so it needs this project-wide set
    /// instead.
    #[serde(default)]
    pub value_only_globals: Arc<HashSet<String>>,
    /// `struct tag or typedef name -> field -> declarator shape`
    /// ([`crate::utility::cert_c::expr_type::declarator_shape`]), for every
    /// field `struct_field_types` records, filed by the same traversal so the
    /// two tables always describe the same definition of a name.
    ///
    /// `struct_field_types` spells a field by its specifiers plus at most one
    /// ` *`, so an array field reads as its element type and `double **p` as
    /// `double *`. Other rules read that spelling as it is, so it keeps it;
    /// this is what a consumer needs to type the field exactly.
    ///
    /// It also files what `struct_field_types` does not hold, so that table's
    /// readers are unmoved: a member inside a preprocessor block of the body,
    /// under its own name, and the members of a named member's anonymous
    /// struct (`struct { u8 ie[1500]; } sme;`) in the SAME struct's table
    /// under the dotted path `"sme.ie"` -- so whatever replaces the struct
    /// replaces its nested members with it. A member (or path) declared
    /// differently in the arms of a conditional has the shape `"?"`: no shape
    /// is known, and a reader must not pick an arm.
    #[serde(default)]
    pub struct_field_shapes: Arc<HashMap<String, HashMap<String, String>>>,
    /// Struct/union typedef aliases: `alias name -> the tag name its fields
    /// are filed under in `struct_field_types``, for every
    /// `typedef struct Tag Alias;` across the scanned files.
    ///
    /// `collect_from_typedef` files a BODIED typedef under both the tag and
    /// the alias, so the gap this closes is the bodyless spelling:
    /// sqlite's `vdbe.h` says `typedef struct sqlite3_value Mem;` while
    /// `vdbeInt.h` declares `struct sqlite3_value { ... }`, so the fields are
    /// filed under `sqlite3_value` and nothing maps `Mem` onto them. The
    /// typedef and the use are routinely in different files, so no file-local
    /// pass can close it.
    ///
    /// Deliberately kept OUT of `struct_field_types` itself. That map is read
    /// by INT30-C, INT32-C, INT33-C and FLP03-C, and filing the alias there
    /// would move four other rules' finding sets as a side effect of an
    /// ARR36-C fix; a consumer opts in by resolving through this map, which
    /// so far only ARR36-C does.
    #[serde(default)]
    pub struct_typedef_aliases: Arc<HashMap<String, String>>,
    /// One-level `typedef` alias map: `alias name -> underlying type text as
    /// written` (e.g. `"paddr_t" -> "word_t"`, `"word_t" -> "unsigned long"`),
    /// collected across every scanned `.c`/`.h` file. Simple scalar aliases
    /// only (`typedef <type> <name>;`) -- struct/union/enum-bodied typedefs
    /// are tracked separately by `struct_field_types`, and pointer/array/
    /// function typedefs are excluded since they don't participate in a
    /// scalar signedness chain.
    ///
    /// A typedef's declaring header is frequently not the file that uses the
    /// alias (seL4's `word_t` family: `paddr_t`/`pptr_t`/`vptr_t`/`seL4_Word`
    /// each typedef onto `word_t`, sometimes from an arch-specific header
    /// different from where `word_t` itself is defined), so resolving one
    /// level locally isn't enough -- a consumer must walk this map
    /// recursively (see `overflow_helpers::typedef_chain_is_unsigned`) and
    /// project-wide.
    #[serde(default)]
    pub typedef_types: Arc<HashMap<String, String>>,
    /// Names of typedefs whose declared type is a function pointer -- e.g.
    /// sqlite's `typedef int (*RecordCompare)(void *, int);` in
    /// `sqliteInt.h`. `collect_from_simple_typedef` filed under
    /// `typedef_types` only stores primitive/sized/named RHSs, so a
    /// function-pointer typedef leaves that map with no entry for its
    /// alias name; DCL31-C needs the *category* (function-pointer
    /// typedef?), not the RHS text, to decide whether a parameter of
    /// that type is directly callable (second consumer of
    /// an earlier fix's shared typedef-chain resolver).
    #[serde(default)]
    pub function_pointer_typedef_names: Arc<HashSet<String>>,
    /// Names of typedefs that hide a pointer in DCL05-C's sense -- a pointer
    /// in the declarator chain, not a function pointer, not a pointer to
    /// const (`declarator_utils::pointer_typedef_names_in`). The typedef is
    /// usually in a header; the `const LPPOINT pt` parameter that the rule
    /// is about is in a .c file that only names the alias.
    #[serde(default)]
    pub pointer_typedef_names: Arc<HashSet<String>>,
    /// `file -> the names that file defines `static` while some other
    /// scanned file does too`: the files whose view of
    /// `function_summaries` is not the shared one.
    ///
    /// Two `static` definitions of one bare name are two unrelated
    /// functions (mbedtls' two `psa_aead_setup`, sqlite's three
    /// `SHA3Update`), so neither may answer under the bare name: whichever
    /// the fold reached first used to answer for every caller in the
    /// project, including the files that define the other one. Each is
    /// kept under its (file, name) key instead, and [`Self::as_seen_from`]
    /// resolves a file's own spelling of the name to its own definition. A
    /// name with no external definition anywhere has no bare entry at all,
    /// which is the sound answer for a caller in neither file -- it cannot
    /// legally call either definition
    /// (`docs/design/multiply-defined-names.md`).
    ///
    /// Keys are canonicalized, because the walk that fills this and the walk
    /// that looks it up need not spell a path the same way.
    #[serde(default)]
    pub scoped_names_by_file: Arc<HashMap<String, Arc<HashSet<String>>>>,
    /// Every file-scope object and enumeration-constant name declared in a
    /// scanned file or resolved header, `extern` declarations and `#if` arms
    /// included: a name a body reads without binding it is one of these, or a
    /// macro, or unknown.
    #[serde(default)]
    pub global_object_names: Arc<HashSet<String>>,
    /// The file-scope objects some scanned file or header declares
    /// `volatile` (`extern volatile int g_ready;`), so a body in another
    /// file reading one reads a volatile object.
    #[serde(default)]
    pub volatile_globals: Arc<HashSet<String>>,
    /// The file-scope objects some scanned file or header declares without
    /// `volatile`: a name in both sets is not known to be volatile. Neither
    /// set holds a source file's `static` objects, which no other file reads.
    #[serde(default)]
    pub non_volatile_globals: Arc<HashSet<String>>,
    /// The file-scope objects some scanned file or header declares with an
    /// array declarator (`extern char cmd[64];`, `u8 ie[1500];`): a body in
    /// another file naming one reads an array, which decays to a pointer
    /// there. A source file's own `static` objects are not here.
    #[serde(default)]
    pub array_globals: Arc<HashSet<String>>,
    /// The file-scope objects some scanned file or header declares without
    /// an array declarator: a name in both sets is not known to be an array
    /// (two unrelated objects share the spelling).
    #[serde(default)]
    pub non_array_globals: Arc<HashSet<String>>,
    /// Typedef names some scanned file or header defines with `volatile`
    /// (`typedef volatile uint32_t reg_t;`).
    #[serde(default)]
    pub volatile_typedefs: Arc<HashSet<String>>,
    /// Every function's side effects closed over the call graph, built on
    /// first use from the tables above and shared by every clone. Never
    /// serialized: it is derived, and rebuilding it costs less than storing
    /// it. Anything that changes `function_summaries` after it may have
    /// been built must call [`Self::invalidate_side_effects`].
    #[serde(skip)]
    pub(crate) side_effects: Arc<std::sync::OnceLock<SideEffectCell>>,
}

impl ProjectContext {
    /// Whether `name` is a constant macro with one value wherever a file
    /// could take it from: every scanned file and header that defines it
    /// writes the same object-like definition, in every live arm
    /// (`macro_definitions`), its value does not vary by configuration
    /// (`config_dependent_constants`), and no system header defines it. A
    /// `macro_constants` entry alone is whichever definition the merge met
    /// last.
    pub fn has_one_project_value(&self, name: &str) -> bool {
        self.macro_constants.contains_key(name)
            && !self.config_dependent_constants.contains(name)
            && !self.macros_defined_outside_project.contains(name)
            && self.macro_definitions.get(name).is_some_and(|defs| {
                matches!(
                    defs.as_slice(),
                    [crate::analyze::check_macros::MacroDefinition::Object { .. }]
                )
            })
    }

    /// The file-scope objects declared as arrays somewhere in the project,
    /// less any name some scanned file or header also declares as something
    /// else: a name two unrelated objects share is not known to be an array.
    pub fn project_array_objects(&self) -> HashSet<String> {
        self.array_globals
            .iter()
            .filter(|n| !self.non_array_globals.contains(*n))
            .cloned()
            .collect()
    }

    /// What calling each scanned function can change, as this context's
    /// file sees the names ([`crate::analyze::side_effects`]).
    pub fn effects(&self) -> EffectView {
        let view = |table, members| EffectView {
            table,
            summaries: self.function_summaries.clone(),
            names: crate::analyze::side_effects::ProjectNames {
                macro_definitions: Arc::clone(&self.macro_definitions),
                volatile_globals: Arc::clone(&self.volatile_globals),
                non_volatile_globals: Arc::clone(&self.non_volatile_globals),
                global_objects: Arc::clone(&self.global_object_names),
                functions: Arc::clone(&self.known_functions),
                constants: Arc::clone(&self.macro_constants),
                macros: Arc::clone(&self.defined_macro_names),
                typedefs: Arc::clone(&self.typedef_types),
                members,
                volatile_typedefs: Arc::clone(&self.volatile_typedefs),
                complete: true,
            },
            function_macros: Arc::clone(&self.function_macros),
            function_macro_arms: Arc::clone(&self.function_macro_arms),
            function_macro_names: Arc::clone(&self.function_macro_names),
            macro_aliases: Arc::clone(&self.macro_aliases),
            struct_field_types: Arc::clone(&self.struct_field_types),
            typedef_types: Arc::clone(&self.typedef_types),
        };
        let (table, members) = self.side_effects.get_or_init(|| {
            let members: Arc<HashSet<String>> = Arc::new(
                self.struct_field_types
                    .values()
                    .flat_map(|fields| fields.keys().cloned())
                    .collect(),
            );
            let unbuilt = view(Arc::default(), Arc::clone(&members));
            let table = crate::analyze::side_effects::EffectTable::build(
                self.function_summaries
                    .raw_entries()
                    .map(|(k, s)| (k, &s.effects)),
                &unbuilt.inputs(),
            );
            (Arc::new(table), members)
        });
        view(Arc::clone(table), Arc::clone(members))
    }

    /// Drop a side-effect table built before `function_summaries` changed.
    pub fn invalidate_side_effects(&mut self) {
        self.side_effects = Arc::default();
    }

    /// An empty context, as if nothing had been pre-scanned yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if the given name was found during the pre-scan.
    pub fn is_known_function(&self, name: &str) -> bool {
        self.known_functions.contains(name)
    }

    /// Returns the summary for a function, if available.
    pub fn get_function_summary(&self, name: &str) -> Option<&FunctionSummary> {
        self.function_summaries.get(name)
    }

    /// Returns `true` if the function has a prototype in a `.h` header file,
    /// indicating it is public API with intentional external linkage.
    pub fn is_header_declared(&self, name: &str) -> bool {
        self.header_declared_functions.contains(name)
    }

    /// Look up the type of a struct field given the struct name and field name.
    /// `struct_name` should be the bare name (e.g., "MyStruct", not "struct MyStruct").
    pub fn get_struct_field_type(&self, struct_name: &str, field_name: &str) -> Option<&str> {
        self.struct_field_types
            .get(struct_name)
            .and_then(|fields| fields.get(field_name))
            .map(|s| s.as_str())
    }

    /// Returns `true` if any cross-file data was collected.
    ///
    /// `header_declared_functions` is included so that a lightweight
    /// header-only prescan (no `-d` flag) still triggers `set_project_context`
    /// on rules like DCL15-C that only need the public-API declaration set.
    pub fn has_cross_file_data(&self) -> bool {
        !self.known_functions.is_empty()
            || !self.function_summaries.is_empty()
            || !self.macro_constants.is_empty()
            || !self.struct_field_types.is_empty()
            || !self.header_declared_functions.is_empty()
            || !self.typedef_types.is_empty()
    }

    /// This context as the file at `path` may use it, or `None` when that is
    /// this context unchanged.
    ///
    /// The returned view differs in two ways. A file that defines a name
    /// some other file also defines `static` sees its own definition in
    /// `function_summaries`: a scope over the shared table, not a copy of
    /// it. It used to be a copy of the summary map, which was cheap only
    /// while few files needed one; in Juliet nearly every file defines a
    /// `static void goodG2B()`, and the copy per file cost more than the
    /// rules did. And a file does not see an alias whose target cannot take
    /// the argument counts the file calls it with
    /// ([`crate::analyze::const_eval::call_arities`]): such a definition is
    /// not the one in force in that file, whichever file it came from.
    pub fn as_seen_from(&self, path: &Path) -> Option<Self> {
        // Nothing to scope: no file pays for resolving its path.
        if self.scoped_names_by_file.is_empty() && self.alias_call_arities.is_empty() {
            return None;
        }
        let key = crate::analyze::compile_commands::real_path(path);
        let statics = self.scoped_names_by_file.get(&key);
        let aliases = self.aliases_seen_from(&key);
        if statics.is_none() && aliases.is_none() {
            return None;
        }
        let mut view = self.clone();
        if let Some(names) = statics {
            view.function_summaries = self.function_summaries.scoped(FileScope {
                file: Arc::from(key.as_str()),
                names: Arc::clone(names),
            });
        }
        if let Some((settled, alternatives)) = aliases {
            view.macro_aliases = Arc::new(settled);
            view.macro_alias_alternatives = Arc::new(alternatives);
        }
        Some(view)
    }

    /// Drop from `alias_call_arities` every name no alias defines, once the
    /// alias tables are complete: only an alias's calls can rule it out.
    pub fn retain_alias_call_arities(&mut self) {
        let aliases = Arc::clone(&self.macro_aliases);
        let alternatives = Arc::clone(&self.macro_alias_alternatives);
        let by_file = Arc::make_mut(&mut self.alias_call_arities);
        for calls in by_file.values_mut() {
            calls.retain(|name, _| aliases.contains_key(name) || alternatives.contains_key(name));
        }
        by_file.retain(|_, calls| !calls.is_empty());
    }

    /// `macro_aliases` and `macro_alias_alternatives` less what the calls
    /// of the file at real path `file` rule out, or `None` when they rule
    /// out nothing.
    fn aliases_seen_from(&self, file: &str) -> Option<AliasTables> {
        use crate::analyze::const_eval;
        let calls: HashMap<String, HashSet<usize>> = self
            .alias_call_arities
            .get(file)?
            .iter()
            .map(|(name, counts)| (name.clone(), counts.iter().copied().collect()))
            .collect();
        // Most files rule nothing out: ask before copying the tables.
        let ruled_out = |name: &String, target: &str| {
            calls.get(name).is_some_and(|counts| {
                const_eval::arity_rules_out(
                    target,
                    counts,
                    &self.macro_aliases,
                    &self.function_arities,
                )
            })
        };
        let any = calls.keys().any(|name| {
            self.macro_alias_alternatives
                .get(name)
                .is_some_and(|targets| targets.iter().any(|t| ruled_out(name, t)))
                || self
                    .macro_aliases
                    .get(name)
                    .is_some_and(|t| ruled_out(name, t))
        });
        if !any {
            return None;
        }
        let mut alternatives = HashMap::clone(&self.macro_alias_alternatives);
        let mut settled = HashMap::clone(&self.macro_aliases);
        let a = const_eval::rule_out_alternatives_by_arity(
            &mut alternatives,
            &calls,
            &self.function_arities,
        );
        let b = const_eval::rule_out_aliases_by_arity(&mut settled, &calls, &self.function_arities);
        (a || b).then_some((settled, alternatives))
    }

    /// Refuse a context loaded from `path` if it was built under a value of
    /// some setting in `current` other than the one in force, naming both.
    ///
    /// A setting the cache does not record was written by a build that did
    /// not yet track it, so its facts were collected the way that build
    /// always collected them: [`BUILT_UNDER_IMPLICIT`] names that value, and
    /// the cache is compared as if it recorded it. A setting with no
    /// registered implicit value is refused when absent, since nothing says
    /// what the cache was built under.
    pub fn check_built_under(
        &self,
        current: &BTreeMap<String, String>,
        path: &Path,
    ) -> anyhow::Result<()> {
        // An empty value (no prescan scope) reads as "(none)".
        let shown = |value: &str| {
            if value.is_empty() {
                "(none)".to_string()
            } else {
                value.to_string()
            }
        };
        for (name, now) in current {
            let then = self.built_under.get(name).map(String::as_str).or_else(|| {
                BUILT_UNDER_IMPLICIT
                    .iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| *value)
            });
            match then {
                Some(then) if then == now => {}
                Some(then) => anyhow::bail!(
                    "prescan cache {} was built with {name} = {}, but this run uses \
                     {name} = {}; re-create it with --save-prescan under the same settings",
                    path.display(),
                    shown(then),
                    shown(now)
                ),
                None => anyhow::bail!(
                    "prescan cache {} does not record the {name} it was built under, and this \
                     run uses {name} = {}; re-create it with --save-prescan",
                    path.display(),
                    shown(now)
                ),
            }
        }
        Ok(())
    }

    /// Save prescan context to a binary cache file.
    pub fn save_to_file(&self, path: &Path) -> anyhow::Result<()> {
        let mut encoded = cache_header().into_bytes();
        encoded.extend(bincode::serialize(self)?);
        std::fs::write(path, &encoded)?;
        Ok(())
    }

    /// Load prescan context from a binary cache file. A cache written by a
    /// different format or aurora-lint version is refused by its header:
    /// bincode is not self-describing, so reading one would fail at best and
    /// silently misread fields at worst.
    pub fn load_from_file(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read(path)?;
        let header = cache_header();
        let Some(body) = data.strip_prefix(header.as_bytes()) else {
            anyhow::bail!(
                "prescan cache {} was written by a different aurora-lint build or cache \
                 format (expected header {:?}); re-create it with --save-prescan",
                path.display(),
                header.trim_end()
            );
        };
        let context: Self = bincode::deserialize(body)?;
        Ok(context)
    }
}

/// For each setting [`ProjectContext::built_under`] records, the value a cache
/// written before the setting was recorded was built under: what the
/// collection did before the setting existed. A new key registers its entry
/// here, so an older cache that lacks the key is still judged correctly
/// without a format bump (adding a key does not change the layout).
///
/// Before `prescan_scope` was recorded the prescan read every file it walked,
/// so an older cache was built leaving nothing out. The integer facts the
/// macro constants are resolved with (`int_facts`) have no implicit value: a
/// cache from before they were recorded took them from a data model alone.
/// Before `closed_program` was recorded no caller set was closed by
/// declaration. Before `generated_headers` was recorded no context was split
/// around build-generated headers.
pub const BUILT_UNDER_IMPLICIT: &[(&str, &str)] = &[
    ("include_names", "exact"),
    ("prescan_scope", ""),
    ("closed_program", "false"),
    ("generated_headers", ""),
];

/// Version of the prescan cache's serialized layout. Bump it with any change
/// to a serialized field of [`ProjectContext`] (or of a type it holds), or to
/// what such a field means: the cache header carries it, so an old cache is
/// refused instead of misread.
const PRESCAN_CACHE_FORMAT: u32 = 41;

/// The header a prescan cache file starts with: a magic, the layout version
/// and the aurora-lint version that wrote it.
fn cache_header() -> String {
    format!(
        "aurora-lint-prescan format={} version={}\n",
        PRESCAN_CACHE_FORMAT,
        env!("CARGO_PKG_VERSION")
    )
}

/// The key a (file, name) pair is stored under in a [`ScopedTable`]: a name
/// defined `static` in several scanned files, qualified by the one file whose
/// definition it is. The NUL cannot occur in a C identifier or in a path, so
/// no bare lookup ever lands on one.
pub fn qualified_key(file: &str, name: &str) -> String {
    format!("{file}\0{name}")
}

/// Which file a [`ScopedTable`] is being read from, and the names that file
/// resolves to its own definitions.
#[derive(Debug, Clone)]
pub struct FileScope {
    file: Arc<str>,
    names: Arc<HashSet<String>>,
}

/// A name-keyed project table in which a name several files define `static`
/// is held once per defining file, and read through a file's scope.
///
/// Unscoped, a bare name reads the bare entry and no file's own entries are
/// visible to iteration. Scoped to a file, a bare name that file defines
/// `static` reads that file's own entry instead. A [`qualified_key`] read
/// directly reaches its entry from any scope: that is how a walk that has
/// already resolved a caller to its defining file -- `callers` hands out
/// qualified keys for exactly those callers -- reads that caller's summary
/// from a file that is not its own.
///
/// The per-file entries are held apart from the bare ones, so iterating a
/// scope costs what iterating the old per-file copy did: the bare entries
/// plus this file's own, not every file's.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(bound(
    serialize = "V: serde::Serialize",
    deserialize = "V: serde::Deserialize<'de>"
))]
pub struct ScopedTable<V> {
    entries: Arc<HashMap<String, V>>,
    by_file: Arc<HashMap<String, HashMap<String, V>>>,
    #[serde(skip)]
    scope: Option<FileScope>,
}

impl<V> Default for ScopedTable<V> {
    fn default() -> Self {
        Self {
            entries: Arc::new(HashMap::new()),
            by_file: Arc::new(HashMap::new()),
            scope: None,
        }
    }
}

impl<V> From<HashMap<String, V>> for ScopedTable<V> {
    /// Splits `entries` on [`qualified_key`]: a qualified key goes to its
    /// file's own entries, every other key stays bare.
    fn from(entries: HashMap<String, V>) -> Self {
        let mut bare = HashMap::with_capacity(entries.len());
        let mut by_file: HashMap<String, HashMap<String, V>> = HashMap::new();
        for (key, value) in entries {
            match key.split_once('\0') {
                Some((file, name)) => {
                    by_file
                        .entry(file.to_string())
                        .or_default()
                        .insert(name.to_string(), value);
                }
                None => {
                    bare.insert(key, value);
                }
            }
        }
        Self {
            entries: Arc::new(bare),
            by_file: Arc::new(by_file),
            scope: None,
        }
    }
}

impl<V> ScopedTable<V> {
    /// The shared bare entries, for prescan's own passes that finish a
    /// context before any rule reads it. Copy-on-write, like every other
    /// table.
    pub fn make_mut(&mut self) -> &mut HashMap<String, V>
    where
        V: Clone,
    {
        Arc::make_mut(&mut self.entries)
    }

    /// This table as `scope`'s file reads it. A handle, not a copy.
    pub fn scoped(&self, scope: FileScope) -> Self {
        Self {
            entries: Arc::clone(&self.entries),
            by_file: Arc::clone(&self.by_file),
            scope: Some(scope),
        }
    }

    /// The entry `name` resolves to from this scope.
    pub fn get(&self, name: &str) -> Option<&V> {
        if let Some((file, bare)) = name.split_once('\0') {
            return self.by_file.get(file)?.get(bare);
        }
        match &self.scope {
            Some(scope) if scope.names.contains(name) => self.by_file.get(&*scope.file)?.get(name),
            _ => self.entries.get(name),
        }
    }

    /// The storage key `name` resolves to from this scope: [`qualified_key`]
    /// for a file's own `static`, else the bare name. `None` when nothing
    /// answers.
    pub fn resolve_key(&self, name: &str) -> Option<String> {
        if let Some((file, bare)) = name.split_once('\0') {
            return self
                .by_file
                .get(file)?
                .contains_key(bare)
                .then(|| name.to_string());
        }
        match &self.scope {
            Some(scope) if scope.names.contains(name) => self
                .by_file
                .get(&*scope.file)?
                .contains_key(name)
                .then(|| qualified_key(&scope.file, name)),
            _ => self.entries.contains_key(name).then(|| name.to_string()),
        }
    }

    /// Every entry under its storage key, whatever the scope: bare names and
    /// every file's qualified ones.
    pub fn raw_entries(&self) -> impl Iterator<Item = (String, &V)> + '_ {
        self.entries.iter().map(|(k, v)| (k.clone(), v)).chain(
            self.by_file.iter().flat_map(|(file, names)| {
                names.iter().map(move |(n, v)| (qualified_key(file, n), v))
            }),
        )
    }

    /// Whether `name` resolves to an entry from this scope.
    pub fn contains_key(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Whether the prescan produced no entries at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.by_file.is_empty()
    }

    /// Every entry this scope can name, under the name it would use: the
    /// bare entries it does not shadow and its own file's.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &V)> + '_ {
        let own = self
            .scope
            .as_ref()
            .and_then(|scope| self.by_file.get(&*scope.file));
        self.entries
            .iter()
            .filter(move |(key, _)| {
                self.scope
                    .as_ref()
                    .is_none_or(|scope| !scope.names.contains(key.as_str()))
            })
            .chain(own.into_iter().flatten())
    }

    /// How many entries [`Self::iter`] yields.
    pub fn len(&self) -> usize {
        self.iter().count()
    }
}

/// The closed side-effect table and the member names it was built with.
pub(crate) type SideEffectCell = (
    Arc<crate::analyze::side_effects::EffectTable>,
    Arc<HashSet<String>>,
);

/// The side-effect table as one file reads it: a callee name resolves to the
/// definition that file's summary lookup would (its own `static`, else the
/// shared one). It carries the project tables the table was built from, so a
/// name read outside any call can be judged the same way.
#[derive(Debug, Clone, Default)]
pub struct EffectView {
    table: Arc<crate::analyze::side_effects::EffectTable>,
    summaries: ScopedTable<FunctionSummary>,
    /// What the project knows about undeclared names.
    pub names: crate::analyze::side_effects::ProjectNames,
    function_macros: Arc<HashMap<String, FunctionMacro>>,
    function_macro_arms: Arc<HashMap<String, Vec<crate::analyze::macro_expand::ProjectMacroArm>>>,
    function_macro_names: Arc<HashSet<String>>,
    macro_aliases: Arc<HashMap<String, String>>,
    struct_field_types: Arc<HashMap<String, HashMap<String, String>>>,
    typedef_types: Arc<HashMap<String, String>>,
}

impl EffectView {
    /// What calling `name` can change, when a scanned file defines it.
    pub fn get(&self, name: &str) -> Option<&crate::analyze::side_effects::ClosedEffects> {
        self.table.get(&self.summaries.resolve_key(name)?)
    }

    /// What reading `name`, which no declaration in scope binds, can change
    /// ([`crate::analyze::side_effects::name_effects`]). `unknown_is_opaque`
    /// false leaves a name nothing knows as reading nothing.
    pub fn name_effects(
        &self,
        name: &str,
        unknown_is_opaque: bool,
    ) -> crate::analyze::side_effects::ClosedEffects {
        crate::analyze::side_effects::name_effects(
            name,
            &self.inputs(),
            &|callee| self.get(callee).cloned(),
            unknown_is_opaque,
        )
    }

    fn inputs(&self) -> crate::analyze::side_effects::EffectInputs<'_> {
        crate::analyze::side_effects::EffectInputs {
            names: &self.names,
            function_macros: &self.function_macros,
            function_macro_arms: &self.function_macro_arms,
            function_macro_names: &self.function_macro_names,
            macro_aliases: &self.macro_aliases,
            struct_field_types: &self.struct_field_types,
            typedef_types: &self.typedef_types,
        }
    }
}

/// A function-summary lookup by name, whichever table answers it: prescan's
/// own map while it is still building one, or a [`ScopedTable`] as a file's
/// rules see it.
pub trait SummaryLookup {
    /// The summary `name` resolves to.
    fn get(&self, name: &str) -> Option<&FunctionSummary>;

    /// Whether `name` resolves to a summary.
    fn contains_key(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Whether there is no summary at all.
    fn is_empty(&self) -> bool;

    /// Every (name, summary) this lookup answers, each name once.
    fn entries(&self) -> Box<dyn Iterator<Item = (&String, &FunctionSummary)> + '_>;
}

impl SummaryLookup for HashMap<String, FunctionSummary> {
    fn get(&self, name: &str) -> Option<&FunctionSummary> {
        HashMap::get(self, name)
    }

    fn is_empty(&self) -> bool {
        HashMap::is_empty(self)
    }

    fn entries(&self) -> Box<dyn Iterator<Item = (&String, &FunctionSummary)> + '_> {
        Box::new(self.iter())
    }
}

impl SummaryLookup for ScopedTable<FunctionSummary> {
    fn get(&self, name: &str) -> Option<&FunctionSummary> {
        ScopedTable::get(self, name)
    }

    fn is_empty(&self) -> bool {
        ScopedTable::is_empty(self)
    }

    fn entries(&self) -> Box<dyn Iterator<Item = (&String, &FunctionSummary)> + '_> {
        Box::new(self.iter())
    }
}

impl<T: SummaryLookup + ?Sized> SummaryLookup for std::cell::Ref<'_, T> {
    fn get(&self, name: &str) -> Option<&FunctionSummary> {
        (**self).get(name)
    }

    fn is_empty(&self) -> bool {
        (**self).is_empty()
    }

    fn entries(&self) -> Box<dyn Iterator<Item = (&String, &FunctionSummary)> + '_> {
        (**self).entries()
    }
}

/// Two summary lookups read as one: `first` answers a name it holds, and
/// `then` answers the rest. The borrowed form of cloning `then` and
/// extending it with `first`.
pub struct SummaryOverlay<'a, A: ?Sized, B: ?Sized> {
    /// Answers every name it holds.
    pub first: &'a A,
    /// Answers the names `first` does not.
    pub then: &'a B,
}

impl<A: SummaryLookup + ?Sized, B: SummaryLookup + ?Sized> SummaryLookup
    for SummaryOverlay<'_, A, B>
{
    fn get(&self, name: &str) -> Option<&FunctionSummary> {
        self.first.get(name).or_else(|| self.then.get(name))
    }

    fn is_empty(&self) -> bool {
        self.first.is_empty() && self.then.is_empty()
    }

    fn entries(&self) -> Box<dyn Iterator<Item = (&String, &FunctionSummary)> + '_> {
        Box::new(
            self.first.entries().chain(
                self.then
                    .entries()
                    .filter(|(name, _)| !self.first.contains_key(name)),
            ),
        )
    }
}

/// The struct-field and typedef tables as one file sees them: the project's,
/// with this file's own definitions on top.
///
/// The project tables are keyed by NAME across the whole tree, and a name is
/// not a type: two files may define the same struct tag or typedef name
/// differently (curl defines `struct h3_stream_ctx` once per QUIC backend,
/// with `id` as `uint64_t` in one and `int64_t` in the other), and the merge
/// keeps whichever file it read last. The definition in scope in a file is
/// that file's own, so it wins here; the project entry is the fallback for a
/// name the file only receives through a header, which is not expanded when
/// the file is parsed. When a file redefines nothing differently, both
/// fields are the project's own handles, not copies.
#[derive(Debug, Clone, Default)]
pub struct VisibleTypes {
    /// `struct tag -> field -> type text`, this file's definitions winning.
    pub struct_field_types: Arc<HashMap<String, HashMap<String, String>>>,
    /// `typedef name -> aliased type text`, this file's definitions winning.
    pub typedef_types: Arc<HashMap<String, String>>,
    /// `struct tag or typedef name -> field -> declarator shape`, filed with
    /// `struct_field_types` and overlaid the same way, so the two agree on
    /// which definition of a name is visible.
    pub struct_field_shapes: Arc<HashMap<String, HashMap<String, String>>>,
    /// `typedef name -> struct/union tag` for `typedef struct Tag Alias;`,
    /// this file's winning. Kept apart from `struct_field_types` for the
    /// reason [`ProjectContext::struct_typedef_aliases`] gives; a consumer
    /// opts in by resolving through it.
    pub struct_typedef_aliases: Arc<HashMap<String, String>>,
}

impl VisibleTypes {
    /// `context`'s tables overlaid with the definitions in `root`.
    pub fn for_file(context: &ProjectContext, root: &tree_sitter::Node, source: &str) -> Self {
        let mut own_fields = HashMap::new();
        let mut own_shapes = HashMap::new();
        crate::analyze::prescan::collect_struct_tables(
            root,
            source,
            &mut own_fields,
            &mut own_shapes,
        );
        let mut own_typedefs = HashMap::new();
        crate::analyze::prescan::collect_typedef_aliases(root, source, &mut own_typedefs);
        let mut own_aliases = HashMap::new();
        crate::analyze::prescan::collect_struct_typedef_aliases(root, source, &mut own_aliases);
        Self {
            struct_field_types: overlay(&context.struct_field_types, own_fields),
            typedef_types: overlay(&context.typedef_types, own_typedefs),
            struct_field_shapes: overlay(&context.struct_field_shapes, own_shapes),
            struct_typedef_aliases: overlay(&context.struct_typedef_aliases, own_aliases),
        }
    }
}

/// `fields` with each struct typedef alias also naming its tag's fields.
///
/// A bodyless `typedef struct cte cte_t;` files the fields under the TAG only,
/// so a declaration spelled `cte_t *` resolves no field until the alias names
/// the same field set. An alias that already has fields of its own keeps them.
/// This is a rule's own view of the map, never the prescan's shared
/// `struct_field_types`: other rules read that one, and filing aliases in it
/// would move their finding sets.
pub fn fold_struct_typedef_aliases<'a, 'b>(
    fields: std::borrow::Cow<'a, HashMap<String, HashMap<String, String>>>,
    aliases: impl IntoIterator<Item = (&'b String, &'b String)>,
) -> std::borrow::Cow<'a, HashMap<String, HashMap<String, String>>> {
    let additions: Vec<(String, HashMap<String, String>)> = aliases
        .into_iter()
        .filter(|(alias, _)| !fields.contains_key(alias.as_str()))
        .filter_map(|(alias, tag)| Some((alias.clone(), fields.get(tag)?.clone())))
        .collect();
    let mut fields = fields;
    if !additions.is_empty() {
        fields.to_mut().extend(additions);
    }
    fields
}

/// `project` with `own` on top, sharing `project` when `own` changes nothing.
fn overlay<V: Clone + PartialEq>(
    project: &Arc<HashMap<String, V>>,
    own: HashMap<String, V>,
) -> Arc<HashMap<String, V>> {
    if own.iter().all(|(k, v)| project.get(k) == Some(v)) {
        return Arc::clone(project);
    }
    let mut merged = (**project).clone();
    merged.extend(own);
    Arc::new(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_context_outside_the_configuration_survives_a_prescan_cache() {
        let mut outside = ProjectContext::new();
        Arc::make_mut(&mut outside.known_functions).insert("only_outside".to_string());
        let mut context = ProjectContext::new();
        Arc::make_mut(&mut context.known_functions).insert("generated_accessor".to_string());
        context.outside_configuration = Some(Arc::new(outside));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prescan.bin");
        context.save_to_file(&path).unwrap();
        let loaded = ProjectContext::load_from_file(&path).unwrap();
        assert!(loaded.known_functions.contains("generated_accessor"));
        let outside = loaded.outside_configuration.expect("kept");
        assert!(outside.known_functions.contains("only_outside"));
        assert!(!outside.known_functions.contains("generated_accessor"));
        assert!(outside.outside_configuration.is_none());
    }

    #[test]
    fn a_file_with_no_include_of_its_own_still_reaches_a_forced_generated_header() {
        // `-include gen/defs_gen.h` on every compile line: a file with no
        // #include has no edge of its own, but the forced include reaches it.
        let edges: HashMap<String, Vec<String>> = HashMap::from([(
            String::new(),
            vec![format!("{UNRESOLVED_INCLUDE}gen/defs_gen.h")],
        )]);
        let beyond = HashMap::new();
        let unresolved: HashSet<String> = HashSet::from(["gen/defs_gen.h".to_string()]);
        assert_eq!(
            unresolved_project_headers_reached(
                &edges,
                &beyond,
                &unresolved,
                Path::new("/nowhere/no_includes.c")
            ),
            vec!["gen/defs_gen.h".to_string()]
        );
        // Without forced includes, a file with no edge reaches nothing.
        let none: HashMap<String, Vec<String>> = HashMap::new();
        assert!(unresolved_project_headers_reached(
            &none,
            &beyond,
            &unresolved,
            Path::new("/nowhere/no_includes.c")
        )
        .is_empty());
    }

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn a_recorded_setting_must_match() {
        let ctx = ProjectContext {
            built_under: map(&[("include_names", "case-insensitive")]),
            ..Default::default()
        };
        let path = Path::new("cache.bin");
        assert!(ctx
            .check_built_under(&map(&[("include_names", "case-insensitive")]), path)
            .is_ok());
        let err = ctx
            .check_built_under(&map(&[("include_names", "exact")]), path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("include_names = case-insensitive"), "{err}");
        assert!(err.contains("include_names = exact"), "{err}");
    }

    #[test]
    fn an_unrecorded_setting_is_judged_by_its_implicit_value() {
        // A cache from a build that did not yet record include_names was
        // built with exact matching.
        let ctx = ProjectContext::default();
        let path = Path::new("cache.bin");
        assert!(ctx
            .check_built_under(&map(&[("include_names", "exact")]), path)
            .is_ok());
        assert!(ctx
            .check_built_under(&map(&[("include_names", "case-insensitive")]), path)
            .is_err());
        // A setting with no implicit value cannot be judged when absent: the
        // integer facts constants were resolved with are one, since an old
        // cache took them from the data model alone.
        let err = ctx
            .check_built_under(&map(&[("declarations", "per-file")]), path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not record the declarations"), "{err}");
        let err = ctx
            .check_built_under(&map(&[("int_facts", "int_bits=32")]), path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not record the int_facts"), "{err}");
    }

    #[test]
    fn a_cache_without_a_prescan_scope_was_built_leaving_nothing_out() {
        let ctx = ProjectContext::default();
        let path = Path::new("cache.bin");
        assert!(ctx
            .check_built_under(&map(&[("prescan_scope", "")]), path)
            .is_ok());
        let err = ctx
            .check_built_under(&map(&[("prescan_scope", r#"["tests/**"]"#)]), path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("prescan_scope = (none)"), "{err}");
        assert!(err.contains(r#"prescan_scope = ["tests/**"]"#), "{err}");
    }

    #[test]
    fn a_scoped_cache_is_refused_by_an_unscoped_run() {
        let ctx = ProjectContext {
            built_under: map(&[("prescan_scope", r#"["tests/**"]"#)]),
            ..Default::default()
        };
        let path = Path::new("cache.bin");
        assert!(ctx
            .check_built_under(&map(&[("prescan_scope", r#"["tests/**"]"#)]), path)
            .is_ok());
        assert!(ctx
            .check_built_under(&map(&[("prescan_scope", "")]), path)
            .is_err());
    }
}
