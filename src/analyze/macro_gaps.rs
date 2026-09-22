//! Where the macro-expansion engine is blind, made visible (task 1180).
//!
//! aurora-lint has no preprocessor. `macro_expand` collects function-like
//! `#define`s from every scanned file and expands invocations on demand, and
//! every place it cannot do that is, by design, silent: a variadic macro is
//! skipped, a definition under `#ifdef _WIN32` is dropped, a header not on
//! any search path is never opened, and an invocation of a name nothing
//! defined stays an opaque call. Each of those is the right default for a
//! tool that works with no build system — and each is also a place where a
//! defect can hide from the dataflow rules without any finding saying so.
//!
//! This module records those decisions as [`MacroGap`]s so that
//! `--report-macro-gaps` can print them. It changes nothing about analysis:
//! the definition-side gaps are a by-product of the same line scan the
//! collector already runs ([`macro_expand::scan_function_macro_defines`]),
//! and the invocation-side audit is a separate read-only pass over the
//! analyzed files that runs only when the flag is on.
//!
//! What is deliberately *not* here: a second opinion on whether a macro
//! should have been expanded. Every kind below reports a decision the engine
//! actually made (or an input it never saw), so the report cannot disagree
//! with the analysis it describes.

use super::context::ProjectContext;
use super::dead_regions::DeadRegions;
use super::macro_expand::{self, DefineSkip, FunctionMacro};
use super::macro_semantics;
use crate::parser::CParser;
use crate::utility::cert_c::{ast_utils, std_functions};
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use tree_sitter::Node;

/// One class of blind spot. Ordered as the report prints them: definitions
/// the engine saw and declined first, then inputs it never reached, then
/// invocations it could not resolve.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum MacroGapKind {
    /// A function-like `#define` the collector skipped because it is
    /// variadic — every invocation stays opaque.
    VariadicDefinition,
    /// Skipped because its body uses `#`/`##`.
    PasteDefinition,
    /// Skipped because its parameter list never closes.
    MalformedDefinition,
    /// Dropped because it sits in a branch the scan's assumed configuration
    /// never compiles — `#ifdef _WIN32` under the default POSIX profile, or an
    /// arm a `--compile-commands` declaration rules out. Right for the
    /// configuration assumed; the whole story for nothing else.
    ///
    /// The name is narrower than the kind: about half of these rows are arms
    /// the file itself proves dead, with no assumption involved. Splitting them
    /// needs the substrate's `DeadCodeReason`, which `DeadRegions` currently
    /// discards — aurora_lint task 1429.
    PlatformDeadDefinition,
    /// The same name has more than one live definition in one file, under
    /// conditions the platform profile cannot settle (`#ifdef WPA_TRACE`).
    /// The first one wins; the report names the others.
    AmbiguousDefinition,
    /// The same name is defined differently in two scanned files. Which one
    /// the engine uses depends on scan order, not on which header the
    /// invoking file actually includes.
    ConflictingDefinition,
    /// An `#include` that resolved to no file on the source directory or any
    /// search path, so whatever it defines was never collected.
    UnresolvedInclude,
    /// A call to a macro the collector saw but skipped (see the three
    /// `*Definition` kinds above): known to be a macro, known to be opaque.
    UnexpandableInvocation,
    /// A call whose argument count does not match the definition the engine
    /// holds, so `expand_invocation` returns `None` — usually a sign that a
    /// different `#ifdef` branch's definition is the live one here.
    ArityMismatch,
    /// A call to a name that no scanned file defines or declares and that is
    /// not a C standard-library function. If it is a macro, its header was
    /// never scanned; if a function, its prototype was not.
    UnknownCallee,
}

impl MacroGapKind {
    /// Heading for the human-readable report.
    pub fn heading(self) -> &'static str {
        match self {
            MacroGapKind::VariadicDefinition => "variadic macro definitions (never expanded)",
            MacroGapKind::PasteDefinition => "macro definitions using # / ## (never expanded)",
            MacroGapKind::MalformedDefinition => "macro definitions the scanner could not parse",
            MacroGapKind::PlatformDeadDefinition => {
                "macro definitions dropped as dead under the scan's assumed configuration"
            }
            MacroGapKind::AmbiguousDefinition => {
                "macros defined more than once in one file (first definition used)"
            }
            MacroGapKind::ConflictingDefinition => {
                "macros defined differently in two files (scan order decides)"
            }
            MacroGapKind::UnresolvedInclude => "#include directives that resolved to no file",
            MacroGapKind::UnexpandableInvocation => "invocations of macros the engine cannot expand",
            MacroGapKind::ArityMismatch => {
                "invocations whose argument count does not match the held definition"
            }
            MacroGapKind::UnknownCallee => {
                "calls to names no scanned file defines or declares (macro from an unscanned header?)"
            }
        }
    }

    /// Kinds whose per-gap `count` aggregates repeated sites of one name in
    /// one file, so a call made a hundred times is one line, not a hundred.
    fn aggregates_per_name(self) -> bool {
        matches!(
            self,
            MacroGapKind::UnexpandableInvocation
                | MacroGapKind::ArityMismatch
                | MacroGapKind::UnknownCallee
        )
    }
}

/// One blind spot, at one place.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MacroGap {
    /// Which class of blind spot this is.
    pub kind: MacroGapKind,
    /// File the gap is anchored to: the file holding the definition, the
    /// file containing the `#include` or the call. Empty only for an
    /// include recorded while walking a header whose includer is not
    /// tracked.
    pub file: String,
    /// 1-based line; 0 when unknown.
    pub line: usize,
    /// The macro, header path or callee name.
    pub name: String,
    /// One sentence a reader can act on.
    pub detail: String,
    /// How many sites this row stands for (invocation kinds aggregate per
    /// name per file; the first site's line is kept).
    pub count: usize,
}

/// Definition-side result for one file: the gaps, plus the line of the
/// definition the collector would keep for each name (so a later conflict
/// can point at it).
#[derive(Debug, Default, Clone)]
pub struct DefinitionAudit {
    /// Definition-side gaps found in the file.
    pub gaps: Vec<MacroGap>,
    /// Name → 1-based line of the definition the collector keeps.
    pub kept_lines: HashMap<String, usize>,
}

/// Audit every function-like `#define` in one file with the collector's own
/// verdicts: skipped (and why), platform-dead, or one of several live
/// definitions of the same name.
///
/// `file` is only stored, never opened. Mirrors `collect_function_macros`'s
/// arbitration exactly — dead-region filtering first, first-wins among what
/// remains — so "the definition used" here is the one the engine holds.
pub fn audit_definitions(source: &str, file: &str) -> DefinitionAudit {
    let dead = DeadRegions::of(source);
    let mut audit = DefinitionAudit::default();
    // name -> every live, parseable definition in file order.
    let mut live: BTreeMap<String, Vec<(usize, FunctionMacro)>> = BTreeMap::new();

    for def in macro_expand::scan_function_macro_defines(source) {
        if dead.contains_line(def.line) {
            audit.gaps.push(MacroGap {
                kind: MacroGapKind::PlatformDeadDefinition,
                file: file.to_string(),
                line: def.line,
                name: def.name,
                detail: "inside a conditional branch the scan's assumed configuration never \
                         compiles; definition dropped"
                    .to_string(),
                count: 1,
            });
            continue;
        }
        match def.outcome {
            Err(skip) => audit.gaps.push(MacroGap {
                kind: skip_kind(skip),
                file: file.to_string(),
                line: def.line,
                name: def.name,
                detail: skip.describe().to_string(),
                count: 1,
            }),
            Ok(m) => live.entry(def.name).or_default().push((def.line, m)),
        }
    }

    for (name, defs) in live {
        let (first_line, first) = &defs[0];
        audit.kept_lines.insert(name.clone(), *first_line);
        let others: Vec<String> = defs[1..]
            .iter()
            .filter(|(_, m)| !m.same_expansion(first))
            .map(|(line, _)| line.to_string())
            .collect();
        if !others.is_empty() {
            audit.gaps.push(MacroGap {
                kind: MacroGapKind::AmbiguousDefinition,
                file: file.to_string(),
                line: *first_line,
                name,
                detail: format!(
                    "also defined differently at line{} {}; the definition at line {} is used \
                     for every invocation",
                    if others.len() == 1 { "" } else { "s" },
                    others.join(", "),
                    first_line
                ),
                count: 1,
            });
        }
    }
    audit
}

fn skip_kind(skip: DefineSkip) -> MacroGapKind {
    match skip {
        DefineSkip::Variadic => MacroGapKind::VariadicDefinition,
        DefineSkip::PasteOrStringize => MacroGapKind::PasteDefinition,
        DefineSkip::Malformed => MacroGapKind::MalformedDefinition,
    }
}

/// A [`MacroGapKind::ConflictingDefinition`] row for `name`, whose definition
/// in `file` (at `line`) lost to the one already held from `kept_in`.
pub fn conflicting_definition(name: &str, file: &str, line: usize, kept_in: &str) -> MacroGap {
    MacroGap {
        kind: MacroGapKind::ConflictingDefinition,
        file: file.to_string(),
        line,
        name: name.to_string(),
        detail: format!(
            "differs from the definition first collected from {kept_in}, which is the one used \
             project-wide"
        ),
        count: 1,
    }
}

/// A [`MacroGapKind::UnresolvedInclude`] row. `includer` is the file
/// naming the header, or `None` when the directive was met while walking a
/// resolved header (whose own path the resolver does not carry), in which
/// case `includer_dir` says where.
pub fn unresolved_include(
    include_path: &str,
    includer: Option<&str>,
    includer_dir: Option<&Path>,
    project_header: bool,
) -> MacroGap {
    let why = if project_header {
        "its directory exists in the project but the file does not (generated at build \
         time?); nothing it defines was collected"
    } else {
        "not found in the including file's directory or on any -I / compile-database / \
         system search path; nothing it defines was collected"
    };
    let detail = match (includer, includer_dir) {
        (None, Some(dir)) => format!("included from a header in {}; {why}", dir.display()),
        _ => why.to_string(),
    };
    MacroGap {
        kind: MacroGapKind::UnresolvedInclude,
        file: includer.unwrap_or_default().to_string(),
        line: 0,
        name: include_path.to_string(),
        detail,
        count: 1,
    }
}

/// Headers and other includable files the `-d` pre-scan walked, keyed for
/// suffix matching, so an `#include "checksum.h"` that no search path
/// places but that sits under a `-d` directory is not reported: the
/// pre-scan already collected everything in it. Only `.h` counts — the
/// pre-scan walks nothing else, so an `#include "table.inc"` under `-d` is
/// still a real gap.
struct PrescannedHeaders {
    paths: Vec<std::path::PathBuf>,
}

impl PrescannedHeaders {
    fn walk(directories: &[String]) -> Self {
        let mut paths = Vec::new();
        for dir in directories {
            for entry in walkdir::WalkDir::new(dir)
                .sort_by_file_name()
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("h"))
            {
                paths.push(entry.into_path());
            }
        }
        Self { paths }
    }

    /// Whether some pre-scanned header ends with `include_path`'s
    /// components (leading `..`/`.` stripped, since those describe the
    /// includer's position, not the header's).
    fn contains(&self, include_path: &str) -> bool {
        let wanted: Vec<&str> = include_path
            .split('/')
            .filter(|c| !c.is_empty() && *c != "." && *c != "..")
            .collect();
        if wanted.is_empty() {
            return false;
        }
        self.paths.iter().any(|p| {
            let comps: Vec<String> = p
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            comps.len() >= wanted.len()
                && comps[comps.len() - wanted.len()..]
                    .iter()
                    .zip(&wanted)
                    .all(|(a, b)| a == b)
        })
    }
}

/// The full report for one scan.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct MacroGapReport {
    /// Every gap, sorted by kind, then file, then line, then name.
    pub gaps: Vec<MacroGap>,
    /// How many function-like macros the engine *does* hold, for scale.
    pub expandable_macros: usize,
    /// Files the invocation audit walked.
    pub files_audited: usize,
    /// Whether `#include` resolution ran at all (it needs at least one
    /// search path); without it, every angle-bracket include is unreachable
    /// by construction and the unresolved-include rows say so.
    pub include_resolution_enabled: bool,
}

impl MacroGapReport {
    /// Per-kind totals, in report order, summing `count`.
    pub fn totals(&self) -> BTreeMap<MacroGapKind, usize> {
        let mut out = BTreeMap::new();
        for g in &self.gaps {
            *out.entry(g.kind).or_insert(0) += g.count;
        }
        out
    }

    /// Human-readable rendering: a totals table, then per kind up to
    /// `per_kind_cap` rows (the JSON export has everything).
    pub fn render_text(&self, per_kind_cap: usize) -> String {
        use std::fmt::Write;
        let mut s = String::new();
        let _ = writeln!(s, "Macro-expansion gap report");
        let _ = writeln!(
            s,
            "  {} expandable function-like macros held; {} files audited; include resolution {}",
            self.expandable_macros,
            self.files_audited,
            if self.include_resolution_enabled {
                "on"
            } else {
                "off (no -I / --compile-commands / --system-includes: angle-bracket includes are \
                 never searched)"
            }
        );
        if self.gaps.is_empty() {
            let _ = writeln!(s, "  no gaps recorded");
            return s;
        }
        let totals = self.totals();
        let _ = writeln!(s);
        for (kind, n) in &totals {
            let _ = writeln!(s, "  {:>7}  {}", n, kind.heading());
        }
        for kind in totals.keys() {
            let rows: Vec<&MacroGap> = self.gaps.iter().filter(|g| g.kind == *kind).collect();
            let _ = writeln!(s);
            let _ = writeln!(s, "{}:", kind.heading());
            for g in rows.iter().take(per_kind_cap) {
                let site = match (g.file.is_empty(), g.line) {
                    (true, _) => String::new(),
                    (false, 0) => format!("{}: ", g.file),
                    (false, line) => format!("{}:{}: ", g.file, line),
                };
                let times = if g.count > 1 {
                    format!(" (x{})", g.count)
                } else {
                    String::new()
                };
                let _ = writeln!(s, "  {}{}{}: {}", site, g.name, times, g.detail);
            }
            if rows.len() > per_kind_cap {
                let _ = writeln!(
                    s,
                    "  ... and {} more (export the report as JSON for the full list)",
                    rows.len() - per_kind_cap
                );
            }
        }
        s
    }
}

/// Build the report: the definition- and include-side gaps the pre-scan
/// already recorded in `context`, plus an invocation audit of every file in
/// `c_files` (parallel, parse-only). `include_paths` is consulted only to
/// decide whether an `#include` in an analyzed file could have resolved.
pub fn build_report(
    c_files: &[String],
    context: &ProjectContext,
    directories: &[String],
    include_paths: &[String],
) -> MacroGapReport {
    let prescanned = PrescannedHeaders::walk(directories);
    // Names the pre-scan saw as macros but will never expand, with the reason
    // — so a call to one is reported as "known-opaque", not "unknown".
    let mut unexpandable: HashMap<&str, MacroGapKind> = HashMap::new();
    for g in &context.macro_gaps {
        if matches!(
            g.kind,
            MacroGapKind::VariadicDefinition
                | MacroGapKind::PasteDefinition
                | MacroGapKind::MalformedDefinition
        ) {
            unexpandable.entry(&g.name).or_insert(g.kind);
        }
    }

    let per_file: Vec<Vec<MacroGap>> = c_files
        .par_iter()
        .map(|file| audit_file(file, context, include_paths, &prescanned, &unexpandable))
        .collect();

    // Analyzed-file rows first: when the same include or definition was
    // also recorded by the pre-scan, the row anchored to the analyzed file
    // is the one a reader can open.
    let mut gaps: Vec<MacroGap> = per_file.into_iter().flatten().collect();
    gaps.extend(context.macro_gaps.iter().cloned());
    normalize_paths(&mut gaps);
    dedupe_and_sort(&mut gaps);

    MacroGapReport {
        gaps,
        expandable_macros: context.function_macros.len(),
        files_audited: c_files.len(),
        include_resolution_enabled: !include_paths.is_empty(),
    }
}

/// One spelling per file, so the pre-scan's `-d src/` walk and the analysis
/// pass's own file list (which may name the same file `./src/a.c` and
/// `/abs/src/a.c`) dedupe against each other; displayed relative to the
/// working directory when under it, like findings are.
fn normalize_paths(gaps: &mut [MacroGap]) {
    let cwd = std::env::current_dir().unwrap_or_default();
    let mut cache: HashMap<String, String> = HashMap::new();
    for g in gaps.iter_mut() {
        if g.file.is_empty() {
            continue;
        }
        let norm = cache
            .entry(g.file.clone())
            .or_insert_with_key(|f| {
                let p = Path::new(f);
                let canon = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
                canon
                    .strip_prefix(&cwd)
                    .map(|r| r.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| canon.to_string_lossy().into_owned())
            })
            .clone();
        g.file = norm;
    }
}

/// Collapse rows that describe the same thing (an include named by many
/// files; a definition recorded by both the pre-scan and the analyzed file
/// itself, when the analyzed tree is also a `-d` directory), then order.
fn dedupe_and_sort(gaps: &mut Vec<MacroGap>) {
    // Unresolved includes are one row per header path project-wide: the
    // question is "was it reachable", not "who asked".
    let mut seen_include: HashSet<String> = HashSet::new();
    let mut seen_site: HashSet<(MacroGapKind, String, usize, String)> = HashSet::new();
    gaps.retain(|g| {
        if g.kind == MacroGapKind::UnresolvedInclude {
            seen_include.insert(g.name.clone())
        } else {
            seen_site.insert((g.kind, g.file.clone(), g.line, g.name.clone()))
        }
    });
    gaps.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.name.cmp(&b.name))
    });
}

/// Invocation- and include-side audit of one analyzed `.c` file.
fn audit_file(
    file: &str,
    context: &ProjectContext,
    include_paths: &[String],
    prescanned: &PrescannedHeaders,
    prescan_unexpandable: &HashMap<&str, MacroGapKind>,
) -> Vec<MacroGap> {
    let mut parser = match CParser::new() {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    let Ok((tree, source)) = parser.parse_file(file) else {
        return Vec::new();
    };
    let root = tree.root_node();
    let mut gaps = Vec::new();

    // Definitions local to this file: the rules see them through the same
    // collector, and a file-local skip is a gap even when the file is not
    // under any -d directory.
    let local_audit = audit_definitions(&source, file);
    let mut unexpandable: HashMap<&str, MacroGapKind> = prescan_unexpandable.clone();
    for g in &local_audit.gaps {
        if matches!(
            g.kind,
            MacroGapKind::VariadicDefinition
                | MacroGapKind::PasteDefinition
                | MacroGapKind::MalformedDefinition
        ) {
            unexpandable.entry(g.name.as_str()).or_insert(g.kind);
        }
    }
    let local_macros = macro_expand::collect_function_macros(&root, &source);
    gaps.extend(local_audit.gaps.iter().cloned());

    // Includes this file names that resolve to nothing the engine read.
    let source_dir = Path::new(file).parent();
    for inc in super::prescan::extract_include_directives(&root, &source) {
        if super::prescan::resolve_header(&inc, source_dir, include_paths).is_some()
            || prescanned.contains(&inc)
        {
            continue;
        }
        // Same classification `resolve_includes` applies, restricted to the
        // includer's own directory (the search paths were judged there).
        let project = context.unresolved_project_headers.contains(&inc)
            || super::prescan::is_missing_project_header(&inc, source_dir, &[]);
        gaps.push(unresolved_include(&inc, Some(file), None, project));
    }

    // Names this file itself declares: functions, parameters, locals,
    // function pointers. A call through any of these is resolved.
    let mut local_names: HashSet<String> = HashSet::new();
    collect_declared_names(&root, &source, &mut local_names);
    let mut local_object_macros: HashSet<String> = HashSet::new();
    ast_utils::collect_defined_macro_names(&source, &mut local_object_macros);

    // Aggregate invocation rows per (kind, name): first line, count.
    let mut calls: BTreeMap<(MacroGapKind, String), (usize, usize, String)> = BTreeMap::new();
    audit_calls(
        &root,
        &source,
        &CallScope {
            context,
            local_macros: &local_macros,
            unexpandable: &unexpandable,
            local_names: &local_names,
            local_object_macros: &local_object_macros,
        },
        &mut calls,
    );
    for ((kind, name), (line, count, detail)) in calls {
        gaps.push(MacroGap {
            kind,
            file: file.to_string(),
            line,
            name,
            detail,
            count,
        });
    }
    gaps
}

struct CallScope<'a> {
    context: &'a ProjectContext,
    local_macros: &'a HashMap<String, FunctionMacro>,
    unexpandable: &'a HashMap<&'a str, MacroGapKind>,
    local_names: &'a HashSet<String>,
    local_object_macros: &'a HashSet<String>,
}

fn audit_calls(
    node: &Node,
    source: &str,
    scope: &CallScope,
    out: &mut BTreeMap<(MacroGapKind, String), (usize, usize, String)>,
) {
    if node.kind() == "call_expression" {
        if let Some((kind, name, detail)) = classify_call(node, source, scope) {
            let line = node.start_position().row + 1;
            let entry = out.entry((kind, name)).or_insert_with(|| (line, 0, detail));
            entry.1 += 1;
            debug_assert!(kind.aggregates_per_name());
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        audit_calls(&child, source, scope, out);
    }
}

/// The verdict on one call, or `None` when the callee is resolved: a held
/// macro with matching arity, a registry-modeled macro, a declared or
/// standard function, or a name this file binds itself.
fn classify_call(
    call: &Node,
    source: &str,
    scope: &CallScope,
) -> Option<(MacroGapKind, String, String)> {
    let callee = call.child_by_field_name("function")?;
    if callee.kind() != "identifier" {
        return None;
    }
    let name = callee.utf8_text(source.as_bytes()).ok()?;
    // `defined(X)` inside `#if` is an operator, not a call; leading
    // underscores are compiler intrinsics (`__builtin_expect`) with no
    // declaration anywhere we could scan (same convention as DCL31-C).
    if name == "defined" || name.starts_with('_') {
        return None;
    }
    let argc = call
        .child_by_field_name("arguments")
        .map(|a| {
            let mut c = a.walk();
            a.named_children(&mut c)
                .filter(|n| n.kind() != "comment")
                .count()
        })
        .unwrap_or(0);

    let held = scope
        .local_macros
        .get(name)
        .or_else(|| scope.context.function_macros.get(name));
    if let Some(m) = held {
        if m.params.len() != argc {
            return Some((
                MacroGapKind::ArityMismatch,
                name.to_string(),
                format!(
                    "held definition takes {} parameter{}, call passes {} argument{}; not expanded \
                     (is a different #ifdef branch's definition the live one here?)",
                    m.params.len(),
                    if m.params.len() == 1 { "" } else { "s" },
                    argc,
                    if argc == 1 { "" } else { "s" }
                ),
            ));
        }
        return None;
    }
    if let Some(kind) = scope.unexpandable.get(name) {
        let why = match kind {
            MacroGapKind::VariadicDefinition => DefineSkip::Variadic.describe(),
            MacroGapKind::PasteDefinition => DefineSkip::PasteOrStringize.describe(),
            _ => DefineSkip::Malformed.describe(),
        };
        return Some((
            MacroGapKind::UnexpandableInvocation,
            name.to_string(),
            format!("defined as a macro the engine skips: {why}"),
        ));
    }
    if macro_semantics::is_registered(name)
        || macro_semantics::is_container_unlink_macro(name)
        || std_functions::is_known_standard_function(name)
        || scope.local_names.contains(name)
        || scope.local_object_macros.contains(name)
        || scope.context.known_functions.contains(name)
        || scope.context.header_declared_functions.contains(name)
        || scope.context.function_summaries.contains_key(name)
        || scope.context.macro_aliases.contains_key(name)
        || scope.context.defined_macro_names.contains(name)
        || scope.context.ambiguous_call_targets.contains(name)
    {
        return None;
    }
    let looks_like_macro = ast_utils::is_likely_macro_constant(name);
    Some((
        MacroGapKind::UnknownCallee,
        name.to_string(),
        if looks_like_macro {
            "ALL_CAPS name with no definition in any scanned file — almost certainly a macro \
             from a header that was not scanned; its effects are invisible to dataflow"
                .to_string()
        } else {
            "no definition or declaration in any scanned file; if it is a macro, the header \
             defining it was not scanned (pass -I / -d / --compile-commands to reach it)"
                .to_string()
        },
    ))
}

/// Every identifier this file binds through a declarator: function
/// definitions and prototypes, parameters, locals and globals, including
/// function-pointer variables. Over-approximate on purpose — the audit only
/// needs "this name is resolved here", never what it is.
fn collect_declared_names(node: &Node, source: &str, out: &mut HashSet<String>) {
    match node.kind() {
        // A heavily macro-decorated file can parse as one `ERROR` whose
        // children are its top-level items (mosquitto's `conf.c`); the
        // declarations in there have no `function_definition` wrapper.
        "ERROR" => out.extend(ast_utils::function_names_in_error_declaration(node, source)),
        "function_definition"
        | "declaration"
        | "parameter_declaration"
        | "field_declaration"
        | "init_declarator" => {
            let mut cursor = node.walk();
            if cursor.goto_first_child() {
                loop {
                    if cursor.field_name() == Some("declarator") {
                        let name =
                            ast_utils::get_identifier_from_declarator(&cursor.node(), source);
                        if !name.is_empty() {
                            out.insert(name);
                        }
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_declared_names(&child, source, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(gaps: &[MacroGap]) -> Vec<(MacroGapKind, &str, usize)> {
        gaps.iter()
            .map(|g| (g.kind, g.name.as_str(), g.line))
            .collect()
    }

    #[test]
    fn definition_audit_reports_each_skip_reason_once() {
        let src = "\
#define OK(a, b) ((a) + (b))
#define LOG(fmt, ...) printf(fmt, __VA_ARGS__)
#define STR(x) #x
#define CAT(a, b) a##b
#define BROKEN(a, b
";
        let audit = audit_definitions(src, "f.h");
        assert_eq!(
            kinds(&audit.gaps),
            vec![
                (MacroGapKind::VariadicDefinition, "LOG", 2),
                (MacroGapKind::PasteDefinition, "STR", 3),
                (MacroGapKind::PasteDefinition, "CAT", 4),
                (MacroGapKind::MalformedDefinition, "BROKEN", 5),
            ]
        );
        assert_eq!(audit.kept_lines.get("OK"), Some(&1));
    }

    #[test]
    fn platform_dead_and_ambiguous_definitions_are_distinguished() {
        // hostap os.h shape: the _MSC_VER arm is dead under POSIX (no gap
        // beyond "dropped"); the WPA_TRACE split is neutral, so both live.
        let src = "\
#ifdef _MSC_VER
#define os_strdup(s) _strdup(s)
#else
#define os_strdup(s) strdup(s)
#endif
#ifdef WPA_TRACE
#define os_free(p) trace_free(p)
#else
#define os_free(p) free(p)
#endif
#ifdef X
#define SAME(a) (a)
#else
#define SAME(a) (a)
#endif
";
        let audit = audit_definitions(src, "os.h");
        assert_eq!(
            kinds(&audit.gaps),
            vec![
                (MacroGapKind::PlatformDeadDefinition, "os_strdup", 2),
                (MacroGapKind::AmbiguousDefinition, "os_free", 7),
            ]
        );
        assert!(audit.gaps[1].detail.contains("line 9"));
        // Identical redefinitions are not ambiguous.
        assert_eq!(audit.kept_lines.get("SAME"), Some(&12));
        assert_eq!(audit.kept_lines.get("os_strdup"), Some(&4));
    }

    #[test]
    fn invocation_audit_classifies_calls() {
        let dir = tempfile::tempdir().unwrap();
        let c = dir.path().join("a.c");
        std::fs::write(
            &c,
            "\
#define SQ(x) ((x) * (x))
#define LOG(fmt, ...) printf(fmt, __VA_ARGS__)
#include \"missing.h\"
#include <stdio.h>
static int helper(int v) { return v; }
int main(int argc, char **argv) {
    int (*fp)(int) = helper;
    int a = SQ(2);
    int b = SQ(1, 2);
    LOG(\"%d\", a);
    LOG(\"%d\", b);
    fp(1);
    printf(\"%d\", a);
    HASH_FIND_INT(users, &a, out);
    MYSTERY(a);
    third_party_call(a);
    __builtin_expect(a, 0);
    return helper(a);
}
",
        )
        .unwrap();
        let context = ProjectContext::new();
        let report = build_report(&[c.to_string_lossy().to_string()], &context, &[], &[]);
        let names: Vec<(MacroGapKind, &str, usize)> = report
            .gaps
            .iter()
            .map(|g| (g.kind, g.name.as_str(), g.count))
            .collect();
        assert_eq!(
            names,
            vec![
                (MacroGapKind::VariadicDefinition, "LOG", 1),
                (MacroGapKind::UnresolvedInclude, "missing.h", 1),
                (MacroGapKind::UnresolvedInclude, "stdio.h", 1),
                (MacroGapKind::UnexpandableInvocation, "LOG", 2),
                (MacroGapKind::ArityMismatch, "SQ", 1),
                (MacroGapKind::UnknownCallee, "MYSTERY", 1),
                (MacroGapKind::UnknownCallee, "third_party_call", 1),
            ]
        );
        assert!(!report.include_resolution_enabled);
        let text = report.render_text(10);
        assert!(text.contains("LOG (x2)"));
        assert!(text.contains("SQ: held definition takes 1 parameter, call passes 2 arguments"));
    }

    #[test]
    fn prescan_gaps_and_unexpandable_names_flow_into_the_report() {
        let dir = tempfile::tempdir().unwrap();
        let c = dir.path().join("b.c");
        std::fs::write(&c, "int f(void) { return CAT(a, b); }\n").unwrap();
        let mut context = ProjectContext::new();
        context.macro_gaps.push(MacroGap {
            kind: MacroGapKind::PasteDefinition,
            file: "x.h".into(),
            line: 3,
            name: "CAT".into(),
            detail: DefineSkip::PasteOrStringize.describe().into(),
            count: 1,
        });
        let report = build_report(&[c.to_string_lossy().to_string()], &context, &[], &[]);
        let names: Vec<(MacroGapKind, &str)> = report
            .gaps
            .iter()
            .map(|g| (g.kind, g.name.as_str()))
            .collect();
        assert_eq!(
            names,
            vec![
                (MacroGapKind::PasteDefinition, "CAT"),
                (MacroGapKind::UnexpandableInvocation, "CAT"),
            ]
        );
        assert_eq!(report.totals()[&MacroGapKind::UnexpandableInvocation], 1);
    }
}
