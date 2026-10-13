//! Shared noreturn-function detection.
//!
//! EXP34-C (and every other CFG-consuming rule -- EXP33-C, MEM01-C, ARR30-C,
//! INT30/31/32/33/34-C) models a function's control flow via
//! [`crate::analyze::cfg`], which only treats `return`/`break`/`continue`/
//! `goto` as terminating a basic block. A call to a function that never
//! returns (`abort()`, a `_Noreturn`-qualified error handler, ...) has
//! exactly the same effect on reachability but wasn't recognized, so a null
//! check whose failure branch calls one of these was invisible to the CFG
//! and the guarded dereference after it looked unguarded. Found on seL4's
//! `src/fastpath/fastpath.c` (an earlier fix's delta-adjudication): `cap_pd`/
//! `reply` are only reached after a NULL check whose failure branch calls
//! `slowpath()`, declared `NORETURN` in `include/arch/*/arch/fastpath/
//! fastpath.h`.
//!
//! This module collects the set of function names known to be noreturn for
//! a translation unit, from three signals:
//! 1. The fixed C standard library list (`abort`, `exit`, ...), trusted only
//!    when the declared environment honors that library contract
//!    (`stdlib_noreturn`: hosted, or a declared libc model).
//! 2. `_Noreturn`-qualified declarations/definitions (C11 6.7.4p8), trusted
//!    only when `trust_noreturn_keyword` holds (the default and strict
//!    policies).
//! 3. A definition whose body unconditionally terminates the process, even
//!    with nothing declaring it noreturn -- pure-ftpd's `pure-pw.c` defines
//!    its own `static void no_mem(void) { fprintf(...); exit(...); }` with
//!    no attribute anywhere. Inferred to a fixpoint, so a wrapper around a
//!    wrapper is recognized too. This is the only proof the pedantic policy
//!    accepts for a project function.
//!
//! A standard library name counts only where the call names the library's
//! function: a file that defines its own `exit` (or declares one `static`)
//! drops it from signal 1 ([`library_names_redefined`]), and a callee that
//! resolves to an object, such as a local function pointer spelled `exit`, is
//! no call to it ([`calls_noreturn`]). Known limitations: an `extern`
//! definition of a library name in another file is not seen, because the
//! prescan keeps no cross-file fact for it; nor is a `static` declaration of
//! one that reaches the file only through an included header, since only the
//! file's own text is read.
//!
//! `__attribute__((noreturn))` is proof under neither policy (ADR-0015): it
//! is a promise the compiler does not check, so a function declared with it
//! is noreturn here only when its body is verified to be. The same holds for
//! a bare-identifier attribute macro such as seL4's `NORETURN`, whose
//! expansion is that attribute: it is not recognized by its spelling at all.
//! The one exception is MSC37-C's `msc37_attribute_noreturn` option, which
//! credits a call to such a function ([`collect_attribute_candidates`]) in the
//! default preset only; those names are kept apart from the sets above, so no
//! other rule sees them. An ISO spelling reached through a macro
//! (`#define NR [[noreturn]]`; `NR void die(void);`) is no attribute in that
//! sense: [`collect_keyword_noreturn_macro_names`] and
//! [`keyword_noreturn_declared_in`] find those, and MSC37-C credits them
//! wherever it trusts the keyword, as it does one written directly.
//!
//! Signals 1 and 2 change what signal 3 infers (a wrapper around `exit` or a
//! `_Noreturn` function is noreturn only when that callee is), so the names
//! are collected once per combination of `stdlib_noreturn` and
//! `trust_noreturn_keyword`, as a [`ByNoreturnTrust`]. A prescan records all
//! four and a rule picks one with
//! [`ByNoreturnTrust::get`], which keeps a saved prescan valid under every
//! setting.

use crate::analyze::check_macros::{collect_conditional_macro_names, MacroDefinition};
use crate::analyze::context::{IncludeClosure, ProjectContext};
use crate::analyze::dead_regions::DeadRegions;
use crate::settings::AnalysisSettings;
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::Path;
use tree_sitter::Node;

/// A value computed under each combination of the two options that decide
/// what counts as noreturn: `trust_noreturn_keyword` (policy: is a `_Noreturn`
/// declaration proof?) and `stdlib_noreturn` (environment: do `abort`, `exit`
/// and the rest honor their library contract?).
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ByNoreturnTrust<T> {
    /// Keyword and library contract both trusted (the default and strict
    /// presets).
    pub keyword_and_stdlib: T,
    /// Only the library contract trusted (the pedantic preset on a declared
    /// libc).
    pub stdlib_only: T,
    /// Only the keyword trusted (default or strict policy with no library
    /// contract: freestanding, or `libc = "custom"`).
    pub keyword_only: T,
    /// Neither: only a body verified never to return (the pedantic preset
    /// with no C library declared), which with no library contract leaves
    /// nothing to verify against.
    pub neither: T,
}

impl<T> ByNoreturnTrust<T> {
    /// The value for `settings`.
    pub fn get(&self, settings: &AnalysisSettings) -> &T {
        match (
            settings.flag("trust_noreturn_keyword"),
            settings.flag("stdlib_noreturn"),
        ) {
            (true, true) => &self.keyword_and_stdlib,
            (false, true) => &self.stdlib_only,
            (true, false) => &self.keyword_only,
            (false, false) => &self.neither,
        }
    }

    /// Apply `f` under each combination.
    pub fn map<U>(&self, f: impl Fn(&T) -> U) -> ByNoreturnTrust<U> {
        ByNoreturnTrust {
            keyword_and_stdlib: f(&self.keyword_and_stdlib),
            stdlib_only: f(&self.stdlib_only),
            keyword_only: f(&self.keyword_only),
            neither: f(&self.neither),
        }
    }
}

/// Noreturn function names under each combination of the noreturn options.
pub type NoreturnNames = ByNoreturnTrust<HashSet<String>>;

impl NoreturnNames {
    /// Add `other`'s names under each combination.
    pub fn extend(&mut self, other: NoreturnNames) {
        self.keyword_and_stdlib.extend(other.keyword_and_stdlib);
        self.stdlib_only.extend(other.stdlib_only);
        self.keyword_only.extend(other.keyword_only);
        self.neither.extend(other.neither);
    }

    /// Drop `other`'s names under each combination.
    pub fn remove_all(&mut self, other: &NoreturnNames) {
        self.keyword_and_stdlib
            .retain(|n| !other.keyword_and_stdlib.contains(n));
        self.stdlib_only.retain(|n| !other.stdlib_only.contains(n));
        self.keyword_only
            .retain(|n| !other.keyword_only.contains(n));
        self.neither.retain(|n| !other.neither.contains(n));
    }
}

/// Standard library functions that never return to their caller: the ISO C
/// set, plus POSIX `_exit` (POSIX.1-2024 `_exit()`), which the hosted
/// ISO C + POSIX library model covers. Trusted only under the
/// `stdlib_noreturn` contract, and `_exit` only where POSIX holds
/// ([`is_stdlib_noreturn_name`]). Known limitation: the cross-file
/// summaries built from this list credit `_exit` whatever the settings say.
///
/// `siglongjmp` is deliberately absent, so it never ends a path: it is
/// POSIX-only and, like `longjmp`, resumes the program elsewhere rather than
/// ending it (see [`NON_TERMINATING_NORETURN_FUNCTIONS`]).
const STDLIB_NORETURN_FUNCTIONS: &[&str] = &[
    "abort",
    "exit",
    "_Exit",
    "_exit",
    "quick_exit",
    "longjmp",
    "thrd_exit",
];

/// True when `name` is one of the standard library's noreturn functions and
/// the declared environment honors that contract (`stdlib_noreturn`). For a
/// rule that recognizes a terminating call by name rather than through a
/// [`collect_noreturn_function_names`] set; either way a scan with no library
/// contract (freestanding, or the pedantic preset with no C library declared)
/// credits none of them.
pub fn is_stdlib_noreturn_name(name: &str, settings: &AnalysisSettings) -> bool {
    settings.flag("stdlib_noreturn")
        && is_stdlib_noreturn_function(name)
        && (!is_posix_only_noreturn_function(name) || settings.posix_holds_project())
}

/// True when `name` is a standard noreturn function only POSIX specifies
/// (`_exit`), which a scan trusts only where POSIX holds.
pub fn is_posix_only_noreturn_function(name: &str) -> bool {
    name.trim() == "_exit"
}

/// True when `name` is one of the standard library's noreturn functions,
/// whatever the declared environment: for a fact computed once for every
/// setting, such as `FunctionSummary::never_returns`. A rule ending paths
/// takes [`is_stdlib_noreturn_name`] instead.
pub fn is_stdlib_noreturn_function(name: &str) -> bool {
    STDLIB_NORETURN_FUNCTIONS.contains(&name.trim())
}

/// Noreturn functions that do **not** end the process: control resumes
/// elsewhere in the same program, so anything still allocated when they are
/// called really is leaked. Callers reasoning about *process termination*
/// (rather than merely "does not return to my caller") must exclude these --
/// see [`is_process_terminating_name`].
const NON_TERMINATING_NORETURN_FUNCTIONS: &[&str] = &["longjmp", "siglongjmp", "thrd_exit"];

/// Depth-first search for a `function_declarator`, descending through
/// `pointer_declarator` wrappers -- mirrors
/// `utility::cert_c::ast_utils::find_function_declarator`, reimplemented
/// here since that one is private to its module.
fn find_function_declarator<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    if node.kind() == "function_declarator" {
        return Some(*node);
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if let Some(found) = find_function_declarator(&child) {
                return Some(found);
            }
        }
    }
    None
}

/// True if `decl_or_def` (a `declaration` or `function_definition` node)
/// declares its function noreturn with an ISO spelling: the C11 `_Noreturn`
/// function specifier, `<stdnoreturn.h>`'s `noreturn` macro for it (which
/// tree-sitter-c parses as the same qualifier), or the C23 `[[noreturn]]`
/// (or deprecated `[[_Noreturn]]`) attribute, on the declaration or its
/// declarator. A prefixed attribute such as `[[gnu::noreturn]]` is a vendor
/// extension and, like `__attribute__((noreturn))`, is not the keyword.
pub fn has_noreturn_keyword(decl_or_def: &Node, source: &str) -> bool {
    let is_keyword = |text: &str| matches!(text.trim(), "_Noreturn" | "noreturn");
    let mut cursor = decl_or_def.walk();
    let qualifier = decl_or_def
        .children(&mut cursor)
        .any(|c| c.kind() == "type_qualifier" && is_keyword(&get_node_text(&c, source)));
    if qualifier {
        return true;
    }
    // `[[noreturn]]` before the declaration, or after the declarator
    // (`void f(void) [[noreturn]];`), but never on a parameter or in a body.
    let body = decl_or_def.child_by_field_name("body");
    let params =
        find_function_declarator(decl_or_def).and_then(|f| f.child_by_field_name("parameters"));
    let outside = |n: &Node| {
        !body.is_some_and(|b| b.start_byte() <= n.start_byte() && n.end_byte() <= b.end_byte())
            && !params
                .is_some_and(|p| p.start_byte() <= n.start_byte() && n.end_byte() <= p.end_byte())
    };
    query::find_descendants_of_kind(*decl_or_def, "attribute")
        .into_iter()
        .filter(|a| outside(a))
        .any(|a| {
            a.child_by_field_name("prefix").is_none()
                && a.child_by_field_name("name")
                    .is_some_and(|name| is_keyword(&get_node_text(&name, source)))
        })
}

/// The noreturn function names `settings` accepts in `root`: the
/// [`collect_noreturn_names`] set it selects.
pub fn collect_noreturn_function_names(
    root: &Node,
    source: &str,
    settings: &AnalysisSettings,
) -> HashSet<String> {
    let names = collect_noreturn_names(root, source);
    names.get(settings).clone()
}

/// The noreturn names a call in `root` can reach: `project` (the prescan's
/// cross-file set) less every function this file defines `static`, plus
/// [`collect_noreturn_function_names`] for `root`. A file's own static is
/// the function its calls reach, so another file's same-named noreturn
/// function must not end a path through it; the file's own noreturn helpers
/// come back through the per-file set. The same holds for a standard library
/// name the file gives its own definition ([`library_names_redefined`]).
pub fn noreturn_names_for_file(
    project: &HashSet<String>,
    root: &Node,
    source: &str,
    settings: &AnalysisSettings,
) -> HashSet<String> {
    let mut own_statics = HashSet::new();
    crate::analyze::prescan::collect_static_function_names(root, source, &mut own_statics);
    own_statics.extend(library_names_redefined(root, source));
    let mut names: HashSet<String> = project.difference(&own_statics).cloned().collect();
    names.extend(collect_noreturn_function_names(root, source, settings));
    names
}

/// The functions `root` declares or defines noreturn with an ISO spelling
/// ([`has_noreturn_keyword`]).
pub fn collect_keyword_noreturn_names(root: &Node, source: &str) -> HashSet<String> {
    let mut declared: HashSet<String> = HashSet::new();
    for node in query::find_descendants_of_kinds(*root, &["declaration", "function_definition"]) {
        let declarator = match node.child_by_field_name("declarator") {
            Some(d) => d,
            None => continue,
        };
        let Some(func_declarator) = find_function_declarator(&declarator) else {
            continue;
        };
        let Some(name_node) = func_declarator.child_by_field_name("declarator") else {
            continue;
        };
        let name = get_node_text(&name_node, source).trim().to_string();
        if name.is_empty() {
            continue;
        }

        if has_noreturn_keyword(&node, source) {
            declared.insert(name);
        }
    }
    declared
}

/// Sentinel standing in the token set of a declaration that carries the GNU
/// noreturn attribute itself, as opposed to a macro that may expand to it.
/// An ISO spelling written directly has none: it is read from the
/// declaration by [`has_noreturn_keyword`].
pub const GNU_NORETURN_DIRECT: &str = "\0gnu-noreturn";

fn identifier_tokens(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|t| !t.is_empty())
}

/// Whether `text` spells the GNU noreturn attribute: `__attribute__((noreturn))`
/// (or `__noreturn__`, among other attributes in the list), or the
/// `[[gnu::noreturn]]` form. Not an ISO spelling, so no policy trusts it
/// ([`spells_keyword_noreturn`] is the other kind); only MSC37-C's
/// `msc37_attribute_noreturn` option credits it.
fn spells_gnu_noreturn_attribute(text: &str) -> bool {
    let is_noreturn = |t: &str| matches!(t, "noreturn" | "__noreturn__");
    let mut rest = text;
    while let Some(at) = rest.find("__attribute__") {
        rest = &rest[at + "__attribute__".len()..];
        let Some(open) = rest.find('(') else { break };
        let mut depth = 0usize;
        let mut end = rest.len();
        for (i, c) in rest[open..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i;
                        break;
                    }
                }
                _ => {}
            }
        }
        if identifier_tokens(&rest[open..end]).any(is_noreturn) {
            return true;
        }
        rest = &rest[end.min(rest.len())..];
    }
    let mut rest = text;
    while let Some(at) = rest.find("[[") {
        rest = &rest[at + 2..];
        let end = rest.find("]]").unwrap_or(rest.len());
        let mut tokens = identifier_tokens(&rest[..end]);
        if matches!(tokens.next(), Some("gnu" | "__gnu__")) && tokens.any(is_noreturn) {
            return true;
        }
        rest = &rest[end..];
    }
    false
}

/// Whether `text` spells an ISO noreturn: the C11 `_Noreturn` specifier or
/// the C23 `[[noreturn]]` attribute. These count for a declaration whatever
/// the spelling's route (directly, or through a macro defined as one), under
/// every preset, by `trust_noreturn_keyword`.
fn spells_keyword_noreturn(text: &str) -> bool {
    if identifier_tokens(text).any(|t| t == "_Noreturn") {
        return true;
    }
    let mut rest = text;
    while let Some(at) = rest.find("[[") {
        rest = &rest[at + 2..];
        let end = rest.find("]]").unwrap_or(rest.len());
        if matches!(
            identifier_tokens(&rest[..end]).next(),
            Some("noreturn" | "__noreturn__" | "_Noreturn")
        ) {
            return true;
        }
        rest = &rest[end..];
    }
    false
}

/// Add to `out` the name of every object-like `#define` in `source` whose
/// replacement list spells the GNU noreturn attribute
/// (`#define NORETURN __attribute__((__noreturn__))`), in any preprocessor
/// branch. What makes a bare identifier an attribute is its definition, not
/// its spelling (ADR-0006): an undefined or differently defined `NORETURN`
/// declares nothing. A chain through a second macro is not followed.
pub fn collect_attribute_noreturn_macro_names(source: &str, out: &mut HashSet<String>) {
    collect_macro_names_spelling(source, spells_gnu_noreturn_attribute, out);
}

/// Add to `out` the name of every object-like `#define` in `source` whose
/// replacement list spells an ISO noreturn (`#define NR [[noreturn]]`,
/// `#define NR _Noreturn`), in any preprocessor branch. The same rule as
/// [`collect_attribute_noreturn_macro_names`], for the spellings every preset
/// credits.
pub fn collect_keyword_noreturn_macro_names(source: &str, out: &mut HashSet<String>) {
    collect_macro_names_spelling(source, spells_keyword_noreturn, out);
}

fn collect_macro_names_spelling(source: &str, spells: fn(&str) -> bool, out: &mut HashSet<String>) {
    for cap in crate::utility::cert_c::ast_utils::define_line_re().captures_iter(source) {
        let body = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        if body.starts_with('(') {
            continue;
        }
        if let Some(name) = cap.get(1).filter(|_| spells(body)) {
            out.insert(name.as_str().to_string());
        }
    }
}

/// The text of a declaration or definition that can hold its attributes: all
/// of it except the parameter list and the body.
fn declaration_head(decl: &Node, source: &str) -> String {
    let mut cut: Vec<(usize, usize)> = Vec::new();
    if let Some(body) = decl.child_by_field_name("body") {
        cut.push((body.start_byte(), body.end_byte()));
    }
    if let Some(params) =
        find_function_declarator(decl).and_then(|f| f.child_by_field_name("parameters"))
    {
        cut.push((params.start_byte(), params.end_byte()));
    }
    cut.sort_unstable();
    let mut head = String::new();
    let mut at = decl.start_byte();
    for (from, to) in cut {
        if from >= at {
            head.push_str(source.get(at..from).unwrap_or(""));
            head.push(' ');
            at = to;
        }
    }
    head.push_str(source.get(at..decl.end_byte()).unwrap_or(""));
    head
}

/// For each function `root` declares or defines, the identifier tokens of
/// its declaration outside the parameter list and body, plus
/// [`GNU_NORETURN_DIRECT`] when it spells the GNU noreturn attribute itself.
/// A name qualifies as declared noreturn by attribute once one of its tokens
/// is an attribute macro ([`attribute_noreturn_declared_in`]); the macro may
/// be defined in a header other than the one holding the declaration, so the
/// join is left to the caller.
///
/// `raw` is the file as written. The parse reads a repaired copy in which a
/// bare identifier the grammar cannot place, such as an attribute macro
/// between the declarator and the `;`, is blanked to spaces; the repair keeps
/// every byte offset, so the declaration's text is sliced from `raw`.
pub fn collect_attribute_candidates(
    root: &Node,
    source: &str,
    raw: &str,
) -> HashMap<String, HashSet<String>> {
    let raw = if raw.len() == source.len() {
        raw
    } else {
        source
    };
    let mut out: HashMap<String, HashSet<String>> = HashMap::new();
    for node in
        query::find_descendants_of_kinds(*root, &["declaration", "function_definition", "ERROR"])
    {
        // A trailing attribute macro the grammar cannot place leaves the
        // declaration as an `ERROR` node holding the function declarator
        // directly: `void halt(void) NORETURN;`.
        let declarator = if node.kind() == "ERROR" {
            let mut cursor = node.walk();
            let direct = node
                .children(&mut cursor)
                .find(|c| c.kind() == "function_declarator");
            if direct.is_none() || get_node_text(&node, raw).contains('{') {
                continue;
            }
            direct
        } else {
            node.child_by_field_name("declarator")
        };
        let Some(declarator) = declarator else {
            continue;
        };
        let Some(name_node) =
            find_function_declarator(&declarator).and_then(|f| f.child_by_field_name("declarator"))
        else {
            continue;
        };
        let name = get_node_text(&name_node, source).trim().to_string();
        if name.is_empty() || name.contains(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
            continue;
        }
        let head = declaration_head(&node, raw);
        let tokens = out.entry(name.clone()).or_default();
        if spells_gnu_noreturn_attribute(&head) {
            tokens.insert(GNU_NORETURN_DIRECT.to_string());
        }
        tokens.extend(
            identifier_tokens(&head)
                .filter(|t| *t != name)
                .map(str::to_string),
        );
    }
    out.retain(|_, tokens| !tokens.is_empty());
    out
}

/// The file at `path` as written, for [`collect_attribute_candidates`]; the
/// parsed `source` itself when it cannot be read.
pub fn raw_text_or(path: &str, source: &str) -> String {
    std::fs::read_to_string(path)
        .ok()
        .filter(|raw| raw.len() == source.len())
        .unwrap_or_else(|| source.to_string())
}

/// The names in `candidates` ([`collect_attribute_candidates`]) declared
/// noreturn by GNU attribute: spelled directly, or through one of
/// `attribute_macros` ([`collect_attribute_noreturn_macro_names`]).
pub fn attribute_noreturn_declared_in(
    candidates: &HashMap<String, HashSet<String>>,
    attribute_macros: &HashSet<String>,
) -> HashSet<String> {
    candidates
        .iter()
        .filter(|(_, tokens)| {
            tokens.contains(GNU_NORETURN_DIRECT)
                || tokens.iter().any(|t| attribute_macros.contains(t))
        })
        .map(|(name, _)| name.clone())
        .collect()
}

/// The names in `candidates` declared noreturn through one of
/// `keyword_macros` ([`collect_keyword_noreturn_macro_names`]): a standard
/// spelling reached by a macro, which [`has_noreturn_keyword`] cannot see in
/// the declaration's text.
pub fn keyword_noreturn_declared_in(
    candidates: &HashMap<String, HashSet<String>>,
    keyword_macros: &HashSet<String>,
) -> HashSet<String> {
    candidates
        .iter()
        .filter(|(_, tokens)| tokens.iter().any(|t| keyword_macros.contains(t)))
        .map(|(name, _)| name.clone())
        .collect()
}

/// Collect the names of every function in `root` recognized as noreturn by
/// the signals documented at module level, under each combination of
/// `trust_noreturn_keyword` and `stdlib_noreturn`.
pub fn collect_noreturn_names(root: &Node, source: &str) -> NoreturnNames {
    let redefined = library_names_redefined(root, source);
    let stdlib: HashSet<String> = STDLIB_NORETURN_FUNCTIONS
        .iter()
        .filter(|s| !redefined.contains(**s))
        .map(|s| s.to_string())
        .collect();
    let declared = collect_keyword_noreturn_names(root, source);

    let infer = |seed: HashSet<String>| {
        let mut names = seed;
        infer_terminating_definitions(root, source, &mut names);
        names
    };
    let with_declared = |mut base: HashSet<String>| {
        base.extend(declared.iter().cloned());
        base
    };
    NoreturnNames {
        keyword_and_stdlib: infer(with_declared(stdlib.clone())),
        stdlib_only: infer(stdlib),
        keyword_only: infer(with_declared(HashSet::new())),
        neither: infer(HashSet::new()),
    }
}

/// Add every function *defined* in `root` whose body unconditionally ends the
/// process, iterating to a fixpoint so a wrapper calling a wrapper, to any
/// depth, is caught too.
///
/// The set only grows, so its fixpoint is unique and does not depend on the
/// order candidates are visited in. A worklist reaches it: every candidate is
/// checked once in name order, and is checked again only when a function it
/// calls at top level has just been added. A fixed number of rounds over a
/// hash map, as this once was, resolved a chain deeper than the round count
/// only when the map happened to visit it in call order, so the same file
/// gave different answers from run to run.
///
/// A name defined more than once (in `#if` arms no platform profile settles)
/// qualifies only when every live definition ends the process: noreturn
/// prunes the paths after a call, so one build whose definition comes back
/// keeps them (ADR-0010 D1). A definition in a platform-dead arm is no build.
///
/// Only process-*terminating* callees seed this. A local wrapper around
/// `longjmp` is genuinely noreturn, but adding it to this set would also make
/// [`is_process_terminating_name`] answer true for it -- that function
/// subtracts a fixed list of spellings, which cannot know about a
/// project-local name. Inferring it would silently convert every allocation
/// live across that wrapper from a real leak into a suppressed one, so the
/// wrapper is deliberately left unrecognized: a miss, not a wrong answer.
fn infer_terminating_definitions(root: &Node, source: &str, names: &mut HashSet<String>) {
    // Only a name all of whose live definitions have no `return` and no
    // `goto` can ever qualify (see `body_unconditionally_terminates`), and
    // that does not change as names are added -- so the candidates are found
    // once, and the worklist only re-asks which of them now call a known
    // terminator.
    let mut candidates: BTreeMap<String, Vec<Node>> = BTreeMap::new();
    let mut returning: HashSet<String> = HashSet::new();
    for (def, name) in live_definitions(root, source) {
        if body_has_no_return_or_goto(&def) {
            candidates.entry(name).or_default().push(def);
        } else {
            returning.insert(name);
        }
    }
    candidates.retain(|name, _| !returning.contains(name));
    // Which candidates call each name in a top-level statement: the only
    // calls `body_unconditionally_terminates` reads.
    let mut callers: HashMap<String, Vec<&str>> = HashMap::new();
    for (name, defs) in &candidates {
        for def in defs {
            let Some(body) = def.child_by_field_name("body") else {
                continue;
            };
            let mut cursor = body.walk();
            for stmt in body.children(&mut cursor) {
                if let Some(callee) = terminating_call_name(&stmt, source) {
                    callers.entry(callee).or_default().push(name.as_str());
                }
            }
        }
    }
    let mut queue: VecDeque<&str> = candidates.keys().map(String::as_str).collect();
    while let Some(name) = queue.pop_front() {
        if names.contains(name) {
            continue;
        }
        if candidates[name]
            .iter()
            .all(|def| body_unconditionally_terminates(def, source, names))
        {
            names.insert(name.to_string());
            if let Some(dependents) = callers.get(name) {
                queue.extend(dependents.iter().copied());
            }
        }
    }
}

/// Every function definition in `root` outside a platform-dead region, with
/// its name.
fn live_definitions<'t>(root: &Node<'t>, source: &str) -> Vec<(Node<'t>, String)> {
    let dead = DeadRegions::of(source);
    query::find_descendants_of_kind(*root, "function_definition")
        .into_iter()
        .filter(|def| !dead.contains_node(def))
        .filter_map(|def| definition_name(&def, source).map(|name| (def, name)))
        .collect()
}

/// The names of the functions `root` defines, outside a platform-dead
/// region, with a body that visibly comes back: it has a `return` or a
/// `goto`, or its last top-level statement calls nothing (so no callee this
/// file cannot see can be what ends it). The project-wide set drops them, so
/// one file's terminating definition does not decide for another file's
/// that returns, while a definition that ends in another file's noreturn
/// function (`die() { log_msg(m); bail(1); }`) is not mistaken for one.
/// `noreturn` is the file's own set, under each combination.
pub fn collect_returning_definitions(
    root: &Node,
    source: &str,
    noreturn: &NoreturnNames,
) -> NoreturnNames {
    let returning: HashSet<String> = live_definitions(root, source)
        .into_iter()
        .filter(|(def, _)| visibly_returns(def))
        .map(|(_, name)| name)
        .collect();
    noreturn.map(|names| returning.difference(names).cloned().collect())
}

/// Whether `def` can come back without relying on what any callee does.
fn visibly_returns(def: &Node) -> bool {
    if !body_has_no_return_or_goto(def) {
        return true;
    }
    let Some(body) = def.child_by_field_name("body") else {
        return false;
    };
    let last = (0..body.named_child_count())
        .rev()
        .filter_map(|i| body.named_child(i))
        .find(|n| n.kind() != "comment");
    match last {
        None => true,
        Some(stmt) => {
            query::find_first_descendant(stmt, |n| n.kind() == "call_expression").is_none()
        }
    }
}

/// Whether `def`'s body contains no `return` and no `goto` anywhere.
fn body_has_no_return_or_goto(def: &Node) -> bool {
    def.child_by_field_name("body").is_some_and(|body| {
        query::find_first_descendant(body, |n| {
            matches!(n.kind(), "return_statement" | "goto_statement")
        })
        .is_none()
    })
}

/// The declared name of a `function_definition`, or `None` when its
/// declarator does not resolve to one.
fn definition_name(def: &Node, source: &str) -> Option<String> {
    let declarator = def.child_by_field_name("declarator")?;
    let func_declarator = find_function_declarator(&declarator)?;
    let name_node = func_declarator.child_by_field_name("declarator")?;
    let name = get_node_text(&name_node, source).trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Whether every call of `def` ends the process.
///
/// Deliberately narrow: the body must contain no `return` and no `goto`
/// anywhere, and one of its *top-level* statements must be a call to a
/// process-terminating function. With no `return` and no `goto`, a top-level
/// statement is reached on every path that does not already diverge earlier,
/// so reaching it is enough -- and both weaker shapes this refuses to reason
/// about (an early `return` above the call, a `goto` jumping over it) are ones
/// where the function really can come back.
fn body_unconditionally_terminates(def: &Node, source: &str, names: &HashSet<String>) -> bool {
    let Some(body) = def.child_by_field_name("body") else {
        return false;
    };
    if !body_has_no_return_or_goto(def) {
        return false;
    }
    let mut cursor = body.walk();
    let terminates = body.children(&mut cursor).any(|stmt| {
        terminating_call_name(&stmt, source)
            .is_some_and(|callee| is_process_terminating_name(&callee, names))
            && stmt
                .child(0)
                .is_some_and(|call| called_function_name(&call, source).is_some())
    });
    terminates
}

/// The callee name of `stmt` when it is an `expression_statement` wrapping a
/// direct call, else `None`.
fn terminating_call_name(stmt: &Node, source: &str) -> Option<String> {
    if stmt.kind() != "expression_statement" {
        return None;
    }
    let call = stmt.child(0).filter(|c| c.kind() == "call_expression")?;
    callee_spelling(&call, source).map(|(_, name)| name)
}

/// `call`'s callee when it is an identifier, read through parentheses and a
/// dereference (`(exit)(1)`, `(*exit)(1)`), with its spelling. Unresolved:
/// see [`called_function_name`].
pub fn callee_spelling<'t>(call: &Node<'t>, source: &str) -> Option<(Node<'t>, String)> {
    let mut function = call.child_by_field_name("function")?;
    // `(exit)(1)` and `(*exit)(1)` both call `exit`: a function designator
    // dereferenced is the same function. A pointer spelled `exit` is still
    // rejected by the caller's binding check.
    loop {
        function = match function.kind() {
            "parenthesized_expression" => function.named_child(0)?,
            "pointer_expression"
                if function
                    .child_by_field_name("operator")
                    .is_some_and(|op| op.kind() == "*") =>
            {
                function.child_by_field_name("argument")?
            }
            _ => break,
        };
    }
    (function.kind() == "identifier").then(|| {
        (
            function,
            get_node_text(&function, source).trim().to_string(),
        )
    })
}

/// The function `call` (a `call_expression`) names directly: its callee,
/// read through parentheses (`(exit)(1)`), when that is an identifier which
/// does not resolve to an object. A parameter, a local or a file-scope
/// function pointer that happens to be spelled `exit` calls whatever it
/// points at, not the function of that name (ADR-0006), so it is `None`.
///
/// Resolving a binding walks the enclosing scopes, which is too costly to do
/// for every call. A caller that only cares about some names checks the
/// spelling first, as [`calls_noreturn`] does.
pub fn called_function_name(call: &Node, source: &str) -> Option<String> {
    let (function, name) = callee_spelling(call, source)?;
    (!crate::analyze::side_effects::designates_object(&function, source)).then_some(name)
}

/// Whether `call` (a `call_expression`) calls a function in
/// `noreturn_names`: the callee is spelled as one, and that spelling names
/// the function rather than an object ([`called_function_name`]).
pub fn calls_noreturn(call: &Node, source: &str, noreturn_names: &HashSet<String>) -> bool {
    callee_spelling(call, source).is_some_and(|(function, name)| {
        noreturn_names.contains(&name)
            && !crate::analyze::side_effects::designates_object(&function, source)
    })
}

/// Whether `call` (a `call_expression`) calls one of the standard library's
/// noreturn functions: the callee names a function
/// ([`called_function_name`]) on the standard list, the file does not give
/// that name its own definition ([`library_names_redefined`]), and, when
/// `settings` is given, the environment honors the library contract
/// ([`is_stdlib_noreturn_name`]: `stdlib_noreturn`, and POSIX for `_exit`).
/// `None` is for a fact computed once for every setting.
pub fn calls_stdlib_noreturn(
    call: &Node,
    source: &str,
    settings: Option<&AnalysisSettings>,
) -> bool {
    let Some((function, name)) = callee_spelling(call, source) else {
        return false;
    };
    let on_list = match settings {
        Some(settings) => is_stdlib_noreturn_name(&name, settings),
        None => is_stdlib_noreturn_function(&name),
    };
    if !on_list || crate::analyze::side_effects::designates_object(&function, source) {
        return false;
    }
    let mut root = *call;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    !library_names_redefined(&root, source).contains(&name)
}

/// The standard library noreturn names (`exit`, `abort`, ...) that `root`
/// gives its own meaning: a function definition by that name, with any
/// linkage, or a `static` declaration of one. A call in the file then reaches
/// the project's function rather than the library's, so the name is noreturn
/// only if that body is proved to be (the terminating-body inference). A
/// plain prototype (`void exit(int);`) still declares the library function
/// and does not count. Only file-scope declarations are read, and no
/// definition's body is entered, so a call site can afford to ask. A
/// declaration that arrives through an `#include` is not in this file's text
/// and is not seen.
pub fn library_names_redefined(root: &Node, source: &str) -> HashSet<String> {
    library_names_redefined_among(root, source, is_stdlib_noreturn_function)
}

/// [`library_names_redefined`] for any set of library names: those `is_library`
/// accepts that `root` defines, or declares `static`, as functions of its own.
/// A rule that recognises a library call by its callee (FIO40-C's `fgets`)
/// asks this before treating a call by that name as the library's.
pub fn library_names_redefined_among(
    root: &Node,
    source: &str,
    is_library: impl Fn(&str) -> bool,
) -> HashSet<String> {
    let mut found = HashSet::new();
    let mut stack = vec![*root];
    while let Some(node) = stack.pop() {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "function_definition" => {
                    if let Some(name) = definition_name(&child, source) {
                        if is_library(&name) {
                            found.insert(name);
                        }
                    }
                }
                "declaration" => {
                    let mut specs = child.walk();
                    let is_static = child.children(&mut specs).any(|c| {
                        c.kind() == "storage_class_specifier"
                            && get_node_text(&c, source).trim() == "static"
                    });
                    if !is_static {
                        continue;
                    }
                    let mut decls = child.walk();
                    for d in child.children_by_field_name("declarator", &mut decls) {
                        let d = if d.kind() == "init_declarator" {
                            d.child_by_field_name("declarator").unwrap_or(d)
                        } else {
                            d
                        };
                        let name =
                            crate::utility::cert_c::ast_utils::get_identifier_from_declarator(
                                &d, source,
                            );
                        if crate::utility::cert_c::declarator_utils::declares_function(&d)
                            && is_library(&name)
                        {
                            found.insert(name);
                        }
                    }
                }
                _ => stack.push(child),
            }
        }
    }
    found
}

/// Whether `name`, a library function's, means something else anywhere in
/// this file (ADR-0006): the file defines a function by that name or declares
/// one `static` ([`library_names_redefined_among`]), or a macro by that name
/// replaces it in every configuration that compiles the file.
///
/// A macro counts when this file `#define`s it, when a project header in the
/// file's include closure defines it function-like, or when the project
/// defines it object-like anywhere (the prescan records no defining file for
/// an object-like macro, so it is taken to reach every file). It does not
/// count when:
/// - its only definitions sit in a region the file's own conditionals prove
///   dead ([`DeadRegions`]), such as `#if 0`;
/// - it is defined only inside a live `#if`/`#ifdef` arm
///   ([`crate::analyze::check_macros::collect_conditional_macro_names`] for
///   the file, `ProjectContext::conditional_macro_names` for the project),
///   since a build without that arm calls the library function;
/// - it is function-like and the file's include closure does not reach a
///   header that defines it, or there is no file path to start one from;
/// - the prescan saw it only outside the project, in a system header.
///
/// The closure ([`IncludeClosure::of`] over `include_edges`) is built only
/// when a function-like project macro has the name.
///
/// A project's external definition in another file is not seen: a `static`
/// one there is a different function, and the prescan keys a lone `static`
/// definition as it keys an external one. MSC30-C asks it about `rand`,
/// FIO46-C about `fclose`.
pub fn library_function_replaced(
    root: &Node,
    source: &str,
    name: &str,
    project: Option<&ProjectContext>,
    file_path: Option<&Path>,
) -> bool {
    if library_names_redefined_among(root, source, |n| n == name).contains(name) {
        return true;
    }
    let dead = DeadRegions::of(source);
    let defines_here = ["preproc_def", "preproc_function_def"]
        .into_iter()
        .flat_map(|kind| query::find_descendants_of_kind(*root, kind))
        .filter(|def| !dead.contains_node(def))
        .any(|def| {
            def.child_by_field_name("name")
                .is_some_and(|n| get_node_text(&n, source) == name)
        });
    if defines_here {
        return !collect_conditional_macro_names(source).contains(name);
    }
    let Some(project) = project else {
        return false;
    };
    if project.macros_defined_outside_project.contains(name)
        || project.conditional_macro_names.contains(name)
    {
        return false;
    }
    let object_like = project.macro_definitions.get(name).is_some_and(|defs| {
        defs.iter()
            .any(|def| matches!(def, MacroDefinition::Object { .. }))
    });
    if object_like {
        return true;
    }
    let Some(arms) = project.function_macro_arms.get(name) else {
        return false;
    };
    let Some(path) = file_path else {
        return false;
    };
    let closure = IncludeClosure::of(&project.include_edges, path).unwrap_or_default();
    arms.iter()
        .any(|arm| arm.files.iter().any(|file| closure.may_include(file)))
}

/// True if `node` is an `expression_statement` calling one of the C standard
/// library's noreturn functions (`exit`, `abort`, ...). For a caller that has
/// no per-file [`collect_noreturn_function_names`] set to hand; a project's
/// own noreturn wrappers are not recognised this way.
pub fn is_stdlib_noreturn_call_statement(node: &Node, source: &str) -> bool {
    node.kind() == "expression_statement"
        && node
            .child(0)
            .filter(|c| c.kind() == "call_expression")
            .is_some_and(|call| calls_stdlib_noreturn(&call, source, None))
}

/// True if `node` is an `expression_statement` wrapping a direct call to a
/// function in `noreturn_names`.
pub fn is_noreturn_call_statement(
    node: &Node,
    source: &str,
    noreturn_names: &HashSet<String>,
) -> bool {
    if node.kind() != "expression_statement" {
        return false;
    }
    node.child(0)
        .filter(|c| c.kind() == "call_expression")
        .is_some_and(|call| calls_noreturn(&call, source, noreturn_names))
}

/// True if calling `name` ends the process, so memory still held at that
/// point is reclaimed by the OS rather than leaked.
///
/// This is deliberately *narrower* than membership in `noreturn_names`.
/// "Noreturn" only promises control never comes back to the caller, which
/// `longjmp` satisfies while the program keeps running -- an allocation live
/// across it is a genuine leak. Treating the two as the same thing would
/// silently drop real MEM31-C findings, so the non-terminating spellings are
/// subtracted explicitly.
pub fn is_process_terminating_name(name: &str, noreturn_names: &HashSet<String>) -> bool {
    let name = name.trim();
    noreturn_names.contains(name) && !NON_TERMINATING_NORETURN_FUNCTIONS.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::CParser;

    fn parse(src: &str) -> (tree_sitter::Tree, String) {
        let mut parser = CParser::new().expect("parser");
        parser.parse_source(src).expect("parse")
    }

    /// The names the default policy accepts in `src`.
    fn default_names(src: &str) -> HashSet<String> {
        let (tree, source) = parse(src);
        collect_noreturn_names(&tree.root_node(), &source).keyword_and_stdlib
    }

    /// The names the pedantic policy accepts in `src`, on an environment that
    /// honors the library contract (a declared libc).
    fn pedantic_names(src: &str) -> HashSet<String> {
        let (tree, source) = parse(src);
        collect_noreturn_names(&tree.root_node(), &source).stdlib_only
    }

    #[test]
    fn stdlib_names_always_present() {
        for names in [
            default_names("int main(void) { return 0; }\n"),
            pedantic_names("int main(void) { return 0; }\n"),
        ] {
            assert!(names.contains("abort"));
            assert!(names.contains("exit"));
            assert!(names.contains("longjmp"));
        }
    }

    #[test]
    fn c11_noreturn_keyword_is_trusted_only_by_the_default_policy() {
        let src = "_Noreturn void die(void);\n";
        assert!(default_names(src).contains("die"));
        assert!(!pedantic_names(src).contains("die"));
    }

    #[test]
    fn a_wrapper_around_a_keyword_declared_function_follows_the_keyword() {
        let src = "_Noreturn void die(void);\nstatic void bail(void) { die(); }\n";
        assert!(default_names(src).contains("bail"));
        assert!(!pedantic_names(src).contains("bail"));
    }

    #[test]
    fn a_verified_body_is_proof_under_both_policies() {
        let src = "_Noreturn void die(void) { exit(1); }\n";
        assert!(default_names(src).contains("die"));
        assert!(pedantic_names(src).contains("die"));
    }

    #[test]
    fn posix_exit_ends_a_path_and_verifies_a_wrapper_but_siglongjmp_does_not() {
        // pure-ftpd's shape: the wrapper's GNU attribute proves nothing, but
        // its body ends in POSIX _exit(), which the hosted contract trusts.
        let src = "void _EXIT(const int status) __attribute__ ((noreturn));\n\
                   void _EXIT(const int status) { cleanup(); _exit(status); }\n\
                   static void jump(void) { siglongjmp(env, 1); }\n";
        let names = default_names(src);
        assert!(names.contains("_exit"));
        assert!(names.contains("_EXIT"));
        assert!(!names.contains("siglongjmp"));
        assert!(!names.contains("jump"));
    }

    #[test]
    fn iso_spellings_of_the_keyword_are_trusted_like_noreturn() {
        for src in [
            "#include <stdnoreturn.h>\nnoreturn void die(void);\n",
            "[[noreturn]] void die(void);\n",
            "void die(void) [[noreturn]];\n",
            "[[_Noreturn]] void die(void);\n",
        ] {
            assert!(default_names(src).contains("die"), "{src}");
            assert!(!pedantic_names(src).contains("die"), "{src}");
        }
    }

    #[test]
    fn a_prefixed_or_parameter_attribute_is_not_the_keyword() {
        for src in [
            "[[gnu::noreturn]] void die(void);\n",
            "void die(int x [[noreturn]]);\n",
        ] {
            assert!(!default_names(src).contains("die"), "{src}");
        }
    }

    #[test]
    fn gnu_attribute_is_proof_under_neither_policy() {
        for src in [
            "__attribute__((noreturn)) void die(void);\n",
            "void die(void) __attribute__((noreturn));\n",
        ] {
            assert!(!default_names(src).contains("die"), "{src}");
            assert!(!pedantic_names(src).contains("die"), "{src}");
        }
    }

    fn attribute_names(src: &str) -> HashSet<String> {
        let (tree, source) = parse(src);
        let mut macros = HashSet::new();
        collect_attribute_noreturn_macro_names(&source, &mut macros);
        attribute_noreturn_declared_in(
            &collect_attribute_candidates(&tree.root_node(), &source, &source),
            &macros,
        )
    }

    #[test]
    fn gnu_attribute_spellings_declare_a_function_noreturn() {
        for src in [
            "__attribute__((noreturn)) void die(void);\n",
            "void die(void) __attribute__((noreturn));\n",
            "void die(void) __attribute__((cold, __noreturn__));\n",
            "[[gnu::noreturn]] void die(void);\n",
            "#define NORETURN __attribute__((__noreturn__))\nvoid die(void) NORETURN;\n",
            "#define NORETURN __attribute__((__noreturn__))\nNORETURN void die(void);\n",
        ] {
            assert!(attribute_names(src).contains("die"), "{src}");
        }
    }

    fn keyword_macro_names(src: &str) -> HashSet<String> {
        let (tree, source) = parse(src);
        let mut macros = HashSet::new();
        collect_keyword_noreturn_macro_names(&source, &mut macros);
        keyword_noreturn_declared_in(
            &collect_attribute_candidates(&tree.root_node(), &source, &source),
            &macros,
        )
    }

    #[test]
    fn an_iso_spelling_is_no_gnu_attribute_but_is_one_through_a_macro() {
        for src in [
            "[[noreturn]] void die(void);\n",
            "_Noreturn void die(void);\n",
            "#define NORETURN _Noreturn\nNORETURN void die(void);\n",
            "#define NORETURN [[noreturn]]\nNORETURN void die(void);\n",
        ] {
            assert!(!attribute_names(src).contains("die"), "{src}");
        }
        for src in [
            "#define NR _Noreturn\nNR void die(void);\n",
            "#define NR [[noreturn]]\nNR void die(void);\n",
            "#define NR [[noreturn]]\nvoid die(void) NR;\n",
        ] {
            assert!(keyword_macro_names(src).contains("die"), "{src}");
        }
        for src in [
            "#define NR __attribute__((noreturn))\nNR void die(void);\n",
            "#define NR [[gnu::noreturn]]\nNR void die(void);\n",
            "void die(void) NR;\n",
        ] {
            assert!(!keyword_macro_names(src).contains("die"), "{src}");
        }
    }

    #[test]
    fn other_attributes_and_undefined_macros_do_not() {
        for src in [
            "void die(void) __attribute__((format(printf, 1, 2)));\n",
            "void die(void) __attribute__((format(printf, 1, 2), noreturn_like));\n",
            "#define NORETURN\nvoid die(void) NORETURN;\n",
            "void die(void) NORETURN;\n",
            "#define NORETURN\n[[deprecated]] void die(void) NORETURN;\n",
        ] {
            assert!(!attribute_names(src).contains("die"), "{src}");
        }
    }

    #[test]
    fn collect_noreturn_function_names_selects_by_settings() {
        use crate::settings::Preset;
        let (tree, source) = parse("_Noreturn void die(void);\n");
        // Default and strict trust the keyword (CERT MSC37-C-EX2); pedantic
        // accepts only a body verified never to return.
        for (preset, trusted) in [
            (Preset::Default, true),
            (Preset::Strict, true),
            (Preset::Pedantic, false),
        ] {
            let settings = AnalysisSettings::preset(preset);
            assert_eq!(
                collect_noreturn_function_names(&tree.root_node(), &source, &settings)
                    .contains("die"),
                trusted,
                "{preset}"
            );
        }
    }

    #[test]
    fn infers_noreturn_from_a_definition_that_only_exits() {
        let (tree, source) =
            parse("static void no_mem(void) { fprintf(stderr, \"oom\"); exit(1); }\n");
        let names = collect_noreturn_names(&tree.root_node(), &source).keyword_and_stdlib;
        assert!(names.contains("no_mem"));
    }

    /// A chain of terminating wrappers resolves completely, and identically
    /// on every collection: each `HashMap` gets its own random seed, so
    /// collecting many times walks the candidates in many orders.
    #[test]
    fn a_deep_wrapper_chain_resolves_the_same_way_every_time() {
        let (tree, source) = parse(
            "static void w6(void) { w5(); }\n\
             static void w5(void) { w4(); }\n\
             static void w4(void) { w3(); }\n\
             static void w3(void) { w2(); }\n\
             static void w2(void) { w1(); }\n\
             static void w1(void) { fputs(\"fatal\", stderr); exit(1); }\n",
        );
        let want: HashSet<String> = ["w1", "w2", "w3", "w4", "w5", "w6"]
            .into_iter()
            .map(String::from)
            .collect();
        for _ in 0..64 {
            let names = collect_noreturn_names(&tree.root_node(), &source).keyword_and_stdlib;
            let inferred: HashSet<String> =
                names.into_iter().filter(|n| n.starts_with('w')).collect();
            assert_eq!(inferred, want);
        }
    }

    #[test]
    fn a_name_with_a_live_returning_definition_is_not_inferred() {
        let (tree, source) = parse(
            "#ifdef HARD_FAIL\n\
             void fatal(void) { abort(); }\n\
             #else\n\
             void fatal(void) { log_it(); return; }\n\
             #endif\n",
        );
        let names = collect_noreturn_names(&tree.root_node(), &source);
        assert!(!names.keyword_and_stdlib.contains("fatal"));
        let returning = collect_returning_definitions(&tree.root_node(), &source, &names);
        assert!(returning.keyword_and_stdlib.contains("fatal"));
    }

    #[test]
    fn a_returning_definition_in_a_platform_dead_arm_does_not_count() {
        // `_WIN32` is dead under the default profile.
        let (tree, source) = parse(
            "#ifdef _WIN32\n\
             void fatal(void) { log_it(); }\n\
             #else\n\
             void fatal(void) { abort(); }\n\
             #endif\n",
        );
        let names = collect_noreturn_names(&tree.root_node(), &source);
        assert!(names.keyword_and_stdlib.contains("fatal"));
        let returning = collect_returning_definitions(&tree.root_node(), &source, &names);
        assert!(!returning.keyword_and_stdlib.contains("fatal"));
    }

    #[test]
    fn infers_through_a_chain_of_wrappers() {
        let (tree, source) = parse(
            "static void die(void) { exit(1); }\n\
             static void bail(void) { die(); }\n",
        );
        let names = collect_noreturn_names(&tree.root_node(), &source).keyword_and_stdlib;
        assert!(names.contains("die"));
        assert!(names.contains("bail"));
    }

    #[test]
    fn does_not_infer_when_an_earlier_return_can_escape() {
        let (tree, source) = parse("static void maybe(int x) { if (x) return; exit(1); }\n");
        let names = collect_noreturn_names(&tree.root_node(), &source).keyword_and_stdlib;
        assert!(!names.contains("maybe"));
    }

    #[test]
    fn does_not_infer_when_the_exit_is_conditional() {
        let (tree, source) = parse("static void maybe(int x) { if (x) { exit(1); } }\n");
        let names = collect_noreturn_names(&tree.root_node(), &source).keyword_and_stdlib;
        assert!(!names.contains("maybe"));
    }

    #[test]
    fn does_not_infer_a_longjmp_wrapper() {
        // Genuinely noreturn, but not process-terminating: inferring it would
        // make `is_process_terminating_name` answer true and turn every
        // allocation live across it into a suppressed leak.
        let (tree, source) = parse("static void unwind(void) { longjmp(env, 1); }\n");
        let names = collect_noreturn_names(&tree.root_node(), &source).keyword_and_stdlib;
        assert!(!names.contains("unwind"));
        assert!(!is_process_terminating_name("unwind", &names));
    }

    #[test]
    fn bare_noreturn_macro_prototype_is_not_proof() {
        // The seL4 shape: NORETURN expands to a GNU attribute, which is
        // proof under neither policy, and the definition's body can return.
        let src = "void NORETURN slowpath(int x);\nvoid slowpath(int x) { for (;;) {} }\n";
        assert!(!default_names(src).contains("slowpath"));
        assert!(!pedantic_names(src).contains("slowpath"));
    }

    #[test]
    fn nothing_is_noreturn_without_the_library_contract_or_the_keyword() {
        // No library contract and no trust in the keyword: the pedantic
        // preset with no C library declared.
        let (tree, source) =
            parse("_Noreturn void die(void);\nstatic void bail(void) { exit(1); }\n");
        let names = collect_noreturn_names(&tree.root_node(), &source);
        assert!(names.neither.is_empty());
        assert!(names.keyword_only.contains("die"));
        assert!(!names.keyword_only.contains("exit"));
        assert!(names.stdlib_only.contains("bail"));
    }

    #[test]
    fn does_not_flag_unrelated_unknown_macro() {
        // An unresolvable macro between the return type and the declarator
        // is blanked, and must not make `foo` noreturn.
        let src = "void VISIBLE foo(void) { return; }\n";
        let (tree, source) = parse(src);
        let names = collect_noreturn_names(&tree.root_node(), &source).keyword_and_stdlib;
        assert!(!names.contains("foo"));
    }

    #[test]
    fn longjmp_is_noreturn_but_not_process_terminating() {
        let names: HashSet<String> = ["longjmp", "siglongjmp", "exit", "abort", "die_mem"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        // Ends the process: memory still held is reclaimed by the OS.
        assert!(is_process_terminating_name("exit", &names));
        assert!(is_process_terminating_name("abort", &names));
        assert!(is_process_terminating_name("die_mem", &names));

        // Noreturn, but the program keeps running -- a live allocation
        // across one of these really is leaked, so it must not suppress.
        assert!(!is_process_terminating_name("longjmp", &names));
        assert!(!is_process_terminating_name("siglongjmp", &names));

        // Not noreturn at all.
        assert!(!is_process_terminating_name("tls_extcert_exit", &names));
    }

    #[test]
    fn is_noreturn_call_statement_matches_expression_statement_call() {
        let src = "void f(void) { abort(); }\n";
        let (tree, source) = parse(src);
        let names = collect_noreturn_names(&tree.root_node(), &source).keyword_and_stdlib;
        let call_stmt =
            query::find_descendants_of_kinds(tree.root_node(), &["expression_statement"])
                .into_iter()
                .next()
                .expect("expression_statement");
        assert!(is_noreturn_call_statement(&call_stmt, &source, &names));
    }
}
