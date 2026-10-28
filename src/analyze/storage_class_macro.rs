// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! Pre-parse pass: spell a storage-class macro (`#define STATIC static`) as
//! the keyword it expands to.
//!
//! Without a preprocessor tree-sitter-c reads `STATIC` as a type name. Before
//! a typedef name the real type then lands in an `ERROR` node and the
//! function definition starts after the macro, so `STATIC myint f(void)`
//! reads as an external function; before `struct { ... }` the object reads
//! as a function definition whose body is the member list. Every rule that
//! asks about linkage, the declared type or the declared name sees the
//! wrong construct.
//!
//! A name is respelled only when every definition the file can see is the
//! same one storage-class specifier: every definition this file writes, in
//! any `#if` arm the file does not prove dead (ADR-0010), and every one the
//! prescan found in a file the file's include closure may reach
//! ([`IncludeClosure`]). A definition in a file it cannot include is another
//! program's, so it neither respells nor vetoes; with no closure (no include
//! graph, or no path to start one from) only the file's own definitions
//! count.
//!
//! A configuration in which the macro is empty or anything else keeps the
//! name as written, so the empty-macro pass reads it as external linkage, as
//! that configuration compiles it. That covers an `#if` arm defining it
//! otherwise (`#ifdef UNIT_TEST` / `#define STATIC` / `#else` / `#define
//! STATIC static`) and a definition only some configurations make
//! ([`collect_conditional_macro_names`]), such as an `#ifndef STATIC` default
//! a `-DSTATIC=` build replaces: a name the file tests with `#ifndef` or
//! `!defined` is taken as such a default. So does an `#undef`: past it the
//! name is no macro, and a file may reuse it as an ordinary identifier. The
//! verdict is per file, not per position, so a file that `#undef`s the name
//! anywhere, or that a file reaching it does, keeps it as written
//! throughout. A name shorter than its keyword is not respelled, since the
//! keyword would not fit in its bytes.
//!
//! The include closure walks `include_edges` only: an include the search
//! path could not resolve
//! ([`include_edges_beyond_search_path`](crate::analyze::context::ProjectContext::include_edges_beyond_search_path))
//! reaches no definition here.
//!
//! Each respelled name is the keyword padded with spaces to the name's
//! length, so every offset and line downstream is unchanged. Comments,
//! literals and preprocessor directives are left as written. Suppression
//! hashes read the file's own text.

use crate::analyze::check_macros::{
    collect_conditional_macro_names, collect_macro_definitions, MacroDefinition,
};
use crate::analyze::context::IncludeClosure;
use crate::utility::cert_c::ast_utils::collect_undefined_macro_names;
use crate::utility::cert_c::pp_tokens::{directive_end, directive_starts, mask_source};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::path::Path;

/// The storage-class specifiers (C11 6.7.1, and the thread-storage spellings
/// tree-sitter-c reads as one) a macro is respelled as.
const STORAGE_CLASSES: &[&str] = &[
    "static",
    "extern",
    "auto",
    "register",
    "typedef",
    "thread_local",
    "__thread",
];

/// One way the project's files define a storage-class macro name, and the
/// files (real paths) that define it that way.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StorageClassDefinition {
    /// The storage class each of those files' definitions spells, or `None`
    /// when a file defines the name otherwise (empty, another body, a
    /// function-like macro) or only in some configurations.
    pub keyword: Option<String>,
    /// Real paths of the files that define it this way.
    pub files: Vec<String>,
}

/// Every name some project file defines as a storage class
/// ([`ProjectContext::storage_class_macros`](crate::analyze::context::ProjectContext::storage_class_macros)),
/// with every way any file defines it.
pub type StorageClassTable = HashMap<String, Vec<StorageClassDefinition>>;

/// What every definition in `definitions` expands to: `Some(Some(kw))` when
/// each is the object-like macro `kw` for one storage class `kw`,
/// `Some(None)` when some definition is a storage class and another is not
/// (or is a different one), and `None` when none is a storage class.
pub fn storage_class_of(definitions: &[MacroDefinition]) -> Option<Option<&'static str>> {
    let mut found: Option<&'static str> = None;
    let mut other = false;
    for definition in definitions {
        let keyword = match definition {
            MacroDefinition::Object { body } => STORAGE_CLASSES
                .iter()
                .copied()
                .find(|kw| body.trim() == *kw),
            _ => None,
        };
        match (keyword, found) {
            (Some(kw), None) => found = Some(kw),
            (Some(kw), Some(seen)) if kw != seen => other = true,
            (Some(_), Some(_)) => {}
            (None, _) => other = true,
        }
    }
    found.map(|kw| (!other).then_some(kw))
}

/// One file's verdict on every name it defines or `#undef`s: `Some(kw)`
/// when each of its definitions is storage class `kw`, every configuration
/// makes one and the file never `#undef`s it, `None` otherwise.
/// `definitions` and `conditional` are [`collect_macro_definitions`] and
/// [`collect_conditional_macro_names`] of `source`; a name the file tests
/// with `#ifndef` or `!defined` ([`names_tested_undefined`]) is a default a
/// build may override.
pub fn file_storage_classes(
    source: &str,
    definitions: &HashMap<String, Vec<MacroDefinition>>,
    conditional: &HashSet<String>,
) -> HashMap<String, Option<&'static str>> {
    let mut undefined = HashSet::new();
    if source.contains("undef") {
        collect_undefined_macro_names(source, &mut undefined);
    }
    let defaults = names_tested_undefined(source);
    let mut out: HashMap<String, Option<&'static str>> = definitions
        .iter()
        .map(|(name, defs)| {
            let keyword = storage_class_of(defs)
                .flatten()
                .filter(|_| !conditional.contains(name) && !defaults.contains(name));
            (name.clone(), keyword)
        })
        .collect();
    // Past an `#undef` the name is no macro, whatever the file defined.
    for name in undefined {
        out.insert(name, None);
    }
    out
}

/// Fold one file's [`file_storage_classes`] into `table` under its real path
/// `file`. Run [`retain_storage_classes`] once every file is in.
pub fn fold_file_storage_classes(
    table: &mut StorageClassTable,
    file: &str,
    verdicts: HashMap<String, Option<&'static str>>,
) {
    for (name, keyword) in verdicts {
        let keyword = keyword.map(str::to_string);
        let entries = table.entry(name).or_default();
        match entries.iter_mut().find(|e| e.keyword == keyword) {
            Some(entry) if entry.files.iter().any(|f| f == file) => {}
            Some(entry) => entry.files.push(file.to_string()),
            None => entries.push(StorageClassDefinition {
                keyword,
                files: vec![file.to_string()],
            }),
        }
    }
}

/// Keep only the names some file defines as a storage class: the rest can
/// never be respelled, and a file's own definitions of them are read from
/// its text.
pub fn retain_storage_classes(table: &mut StorageClassTable) {
    table.retain(|_, entries| entries.iter().any(|e| e.keyword.is_some()));
}

/// [`file_storage_classes`] read straight from a file's text, for the names
/// it defines as a storage class and those `project` holds, which an
/// `#undef` or another definition here vetoes. Empty when there are none.
fn own_storage_classes(
    source: &str,
    project: &HashMap<String, Option<&'static str>>,
) -> HashMap<String, Option<&'static str>> {
    if !source.contains("define") && !source.contains("undef") {
        return HashMap::new();
    }
    let definitions = collect_macro_definitions(source);
    if project.is_empty()
        && !definitions
            .values()
            .any(|defs| storage_class_of(defs).flatten().is_some())
    {
        return HashMap::new();
    }
    let verdicts = file_storage_classes(
        source,
        &definitions,
        &collect_conditional_macro_names(source),
    );
    verdicts
        .into_iter()
        .filter(|(name, keyword)| keyword.is_some() || project.contains_key(name))
        .collect()
}

/// Every name a directive of `source` tests for being undefined: `#ifndef
/// NAME`, or `!defined(NAME)` / `!defined NAME` in an `#if` or `#elif`.
/// Text-level, as the pass runs before any parse; `#ifndef STATIC` /
/// `#define STATIC static` has an include guard's shape, which
/// [`collect_conditional_macro_names`] skips.
pub fn names_tested_undefined(source: &str) -> HashSet<String> {
    let ident = |s: &str| -> String {
        s.chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect()
    };
    let mut out = HashSet::new();
    for start in directive_starts(source) {
        let directive = &source[start + 1..start + directive_end(&source[start..])];
        let directive = directive.trim_start();
        if let Some(rest) = directive.strip_prefix("ifndef") {
            out.insert(ident(rest.trim_start()));
            continue;
        }
        if !(directive.starts_with("if") || directive.starts_with("elif")) {
            continue;
        }
        let mut rest = directive;
        while let Some(at) = rest.find("defined") {
            let negated = rest[..at].trim_end().ends_with('!');
            rest = &rest[at + "defined".len()..];
            if negated {
                let operand = rest.trim_start();
                out.insert(ident(
                    operand.strip_prefix('(').unwrap_or(operand).trim_start(),
                ));
            }
        }
    }
    out.remove("");
    out
}

/// The keyword a definition list spells, as the `&'static str` the pass
/// writes.
fn keyword_named(keyword: &str) -> Option<&'static str> {
    STORAGE_CLASSES.iter().copied().find(|kw| *kw == keyword)
}

/// The verdict of every `table` name some file `path` may include defines:
/// `Some(kw)` when each such definition is `kw`, `None` when they are not.
/// Empty without a path or without an include graph out of the file.
fn reachable_storage_classes(
    table: &StorageClassTable,
    include_edges: &HashMap<String, Vec<String>>,
    path: Option<&Path>,
) -> HashMap<String, Option<&'static str>> {
    let Some(closure) = path
        .filter(|_| !table.is_empty())
        .and_then(|path| IncludeClosure::of(include_edges, path))
    else {
        return HashMap::new();
    };
    let mut out = HashMap::new();
    for (name, entries) in table {
        let mut keywords = entries
            .iter()
            .filter(|e| e.files.iter().any(|f| closure.may_include(f)))
            .map(|e| e.keyword.as_deref().and_then(keyword_named));
        let Some(first) = keywords.next() else {
            continue;
        };
        let agreed = keywords.try_fold(first, |kw, other| (other == kw).then_some(kw));
        out.insert(name.clone(), agreed.flatten());
    }
    out
}

/// `source` with every storage-class macro spelled as its keyword. `table`
/// and `include_edges` are the prescan's
/// [`storage_class_macros`](crate::analyze::context::ProjectContext::storage_class_macros)
/// and `include_edges` (both empty without a prescan), and `path` is the
/// file's, which the include closure starts from. The file's own
/// definitions are read here, and both must agree.
pub fn spell_storage_class_macros<'s>(
    source: &'s str,
    path: Option<&Path>,
    table: &StorageClassTable,
    include_edges: &HashMap<String, Vec<String>>,
) -> Cow<'s, str> {
    let project = reachable_storage_classes(table, include_edges, path);
    let local = own_storage_classes(source, &project);
    let mut spellings: Vec<(&str, &'static str)> = Vec::new();
    for name in local.keys().chain(project.keys()) {
        if spellings.iter().any(|(n, _)| n == name) {
            continue;
        }
        let verdicts = [local.get(name), project.get(name)];
        if verdicts.iter().any(|v| matches!(v, Some(None))) {
            continue;
        }
        let mut keywords = verdicts.iter().filter_map(|v| v.copied().flatten());
        let Some(keyword) = keywords.next() else {
            continue;
        };
        if keywords.any(|other| other != keyword) || name.len() < keyword.len() {
            continue;
        }
        spellings.push((name.as_str(), keyword));
    }
    if spellings.is_empty() {
        return Cow::Borrowed(source);
    }
    let masked = mask_source(source);
    let directives = directive_ranges(source);
    // A byte past ASCII is part of a UTF-8 identifier character, and `$` a
    // GNU identifier character.
    let is_ident = |b: u8| b == b'_' || b == b'$' || b >= 0x80 || b.is_ascii_alphanumeric();
    let in_directive = |at: usize| {
        let k = directives.partition_point(|r| r.start <= at);
        k > 0 && directives[k - 1].contains(&at)
    };
    let bytes = masked.as_bytes();
    let mut out = source.as_bytes().to_vec();
    let mut changed = false;
    for (name, keyword) in spellings {
        for (at, _) in masked.match_indices(name) {
            let end = at + name.len();
            if at > 0 && is_ident(bytes[at - 1]) || bytes.get(end).is_some_and(|&b| is_ident(b)) {
                continue;
            }
            if in_directive(at) {
                continue;
            }
            for (i, b) in out[at..end].iter_mut().enumerate() {
                *b = keyword.as_bytes().get(i).copied().unwrap_or(b' ');
            }
            changed = true;
        }
    }
    if !changed {
        return Cow::Borrowed(source);
    }
    // Only ASCII identifier bytes were written over, so this holds.
    Cow::Owned(String::from_utf8(out).expect("an ASCII substitution keeps UTF-8"))
}

/// Byte ranges of every preprocessor directive in `source`, continuation
/// lines included, in order.
fn directive_ranges(source: &str) -> Vec<Range<usize>> {
    directive_starts(source)
        .into_iter()
        .map(|start| start..start + directive_end(&source[start..]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spell(source: &str) -> String {
        spell_storage_class_macros(source, None, &HashMap::new(), &HashMap::new()).into_owned()
    }

    /// A project table and include graph: `files` define their names as
    /// given, and `edges` say who includes whom.
    fn project(
        files: &[(&str, &str)],
        edges: &[(&str, &[&str])],
    ) -> (StorageClassTable, HashMap<String, Vec<String>>) {
        let mut table = StorageClassTable::new();
        for (file, source) in files {
            let defs = collect_macro_definitions(source);
            let conditional = collect_conditional_macro_names(source);
            let verdicts = file_storage_classes(source, &defs, &conditional);
            fold_file_storage_classes(&mut table, file, verdicts);
        }
        retain_storage_classes(&mut table);
        let edges = edges
            .iter()
            .map(|(from, to)| (from.to_string(), to.iter().map(|t| t.to_string()).collect()))
            .collect();
        (table, edges)
    }

    #[test]
    fn a_storage_class_macro_is_respelled_in_place() {
        let source = "#define STATIC static\n#define PRIVATE static\nSTATIC int f(void);\n\
                      PRIVATE myint g;\n";
        let spelled = spell(source);
        assert_eq!(spelled.len(), source.len());
        assert_eq!(
            spelled,
            "#define STATIC static\n#define PRIVATE static\nstatic int f(void);\n\
             static  myint g;\n"
        );
    }

    #[test]
    fn a_macro_empty_in_some_configuration_is_kept() {
        let source = "#ifdef UNIT_TEST\n#define STATIC\n#else\n#define STATIC static\n#endif\n\
                      STATIC int f(void);\n";
        assert_eq!(spell(source), source);
    }

    #[test]
    fn a_default_a_build_may_override_is_kept() {
        let source = "#ifndef STATIC\n#define STATIC static\n#endif\nSTATIC int f(void);\n";
        assert_eq!(spell(source), source);
        let source = "#if !defined(STATIC)\n#define STATIC static\n#endif\nSTATIC int f(void);\n";
        assert_eq!(spell(source), source);
        let guarded = "#ifndef UTIL_H\n#define UTIL_H\n#define STATIC static\n\
                       STATIC int f(void);\n#endif\n";
        assert!(spell(guarded).contains("\nstatic int f(void);\n"));
    }

    #[test]
    fn every_arm_spelling_the_same_class_is_respelled() {
        let source = "#ifdef A\n#define LOCAL_FN static\n#else\n#define LOCAL_FN static\n#endif\n\
                      LOCAL_FN int f(void);\n";
        assert!(spell(source).contains("\nstatic   int f(void);\n"));
    }

    #[test]
    fn a_name_shorter_than_its_keyword_comments_and_literals_are_kept() {
        let source = "#define LOCAL static\nLOCAL int f(void);\n";
        assert_eq!(spell(source), source);
        let source = "#define STATIC static\nconst char *s = \"STATIC\"; /* STATIC */\n\
                      int STATICS, MY_STATIC, x$STATIC, f\u{e9}STATIC;\n";
        assert_eq!(spell(source), source);
    }

    #[test]
    fn a_header_the_file_includes_respells_and_vetoes() {
        let (table, edges) = project(
            &[
                ("/p/util.h", "#define STATIC static\n"),
                ("/p/stub.h", "#define STATIC\n"),
            ],
            &[
                ("/p/a.c", &["/p/util.h"]),
                ("/p/b.c", &["/p/util.h", "/p/stub.h"]),
            ],
        );
        let use_ = "STATIC int f(void);\n";
        let spell_in = |path: &str| {
            spell_storage_class_macros(use_, Some(Path::new(path)), &table, &edges).into_owned()
        };
        assert_eq!(spell_in("/p/a.c"), "static int f(void);\n");
        assert_eq!(spell_in("/p/b.c"), use_);
    }

    #[test]
    fn the_files_own_other_definition_vetoes_a_header() {
        let (table, edges) = project(
            &[("/p/util.h", "#define STATIC static\n")],
            &[("/p/c.c", &["/p/util.h"])],
        );
        let source = "#undef STATIC\n#define STATIC\nSTATIC int f(void);\n";
        assert_eq!(
            spell_storage_class_macros(source, Some(Path::new("/p/c.c")), &table, &edges),
            source
        );
    }

    #[test]
    fn an_undef_keeps_the_name() {
        let source = "#define STATIC static\nSTATIC int f(void);\n#undef STATIC\n\
                      int g(void) { int STATIC = 1; return STATIC; }\n";
        assert_eq!(spell(source), source);
        let (table, edges) = project(
            &[(
                "/p/h.h",
                "#define STATIC static\nSTATIC int hf(void);\n#undef STATIC\n",
            )],
            &[("/p/a.c", &["/p/h.h"])],
        );
        let includer = "int g(void) { int STATIC = 1; return STATIC; }\n";
        assert_eq!(
            spell_storage_class_macros(includer, Some(Path::new("/p/a.c")), &table, &edges),
            includer
        );
        // A file that only `#undef`s a header's macro keeps it too.
        let (table, edges) = project(
            &[("/p/util.h", "#define STATIC static\n")],
            &[("/p/b.c", &["/p/util.h"])],
        );
        let undefines = "#undef STATIC\nint g(void) { int STATIC = 1; return STATIC; }\n";
        assert_eq!(
            spell_storage_class_macros(undefines, Some(Path::new("/p/b.c")), &table, &edges),
            undefines
        );
    }

    #[test]
    fn a_definition_the_file_cannot_include_does_not_count() {
        let (table, edges) = project(
            &[
                ("/p/mod.c", "#define PRIVATE static\n"),
                ("/p/stub.h", "#define STATIC\n"),
            ],
            &[("/p/other.c", &["/p/types.h"])],
        );
        let other = "int f(int v) { int PRIVATE = v; return PRIVATE; }\n";
        assert_eq!(
            spell_storage_class_macros(other, Some(Path::new("/p/other.c")), &table, &edges),
            other
        );
        // Its own definition stands though a stub elsewhere defines it empty.
        let own = "#define STATIC static\nSTATIC int g(void);\n";
        assert!(
            spell_storage_class_macros(own, Some(Path::new("/p/other.c")), &table, &edges)
                .contains("\nstatic int g(void);\n")
        );
        // With no include graph out of the file, only its own text counts.
        assert_eq!(
            spell_storage_class_macros(other, Some(Path::new("/p/x.c")), &table, &edges),
            other
        );
    }

    #[test]
    fn a_respelled_definition_parses() {
        let source = spell(
            "#define STATIC static\ntypedef int myint;\nSTATIC myint f(void) { return 2; }\n",
        );
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(&source, None).unwrap();
        assert!(!tree.root_node().has_error());
    }
}
