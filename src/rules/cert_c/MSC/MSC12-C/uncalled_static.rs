// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! MSC12-C's uncalled-static form: a `static` function that no code which
//! runs calls, and whose address never escapes, is code that is never
//! executed (MSC12-C/2026-11-23/scope-uncalled-static).
//!
//! # What counts as a use
//!
//! An occurrence of the function's name, outside its own definitions and
//! file-scope prototypes, that resolves to the file-scope function by
//! declaration (ADR-0006): a call, or the name as a value. An occurrence in
//! an arm the file proves is never compiled does not count; one in any other
//! arm does (ADR-0010). A call from a function's own body is no use of it.
//! A use inside another `static` function's body is a caller; under the
//! default policy's `msc12_dead_callers` it counts only if that function is
//! itself live, so a chain or a cycle of statics that nothing live reaches
//! is reported, each function once, as called only from code that never
//! runs (MSC12-C/2026-11-24/dead-callers).
//!
//! The function is also live when:
//!
//! - the file's own text names it somewhere the parse does not read as code,
//!   such as a `#define` body (even one never expanded) or a `#pragma`;
//! - a `#define` in this file or its include closure pastes it with `##`
//!   from a literal fragment (`parse_##name`; a macro's parameters are not
//!   fragments);
//! - a file in its include closure spells it: a header's prototype, a
//!   template header's code, an X-macro list included into an initializer;
//! - an invocation of a function-like macro that nothing defines (a header
//!   the scan cannot see) passes an identifier the name begins or ends with
//!   at a `_` boundary: `G_DEFINE_TYPE(Foo, foo, ...)` pastes `foo_init`;
//! - a string in an attribute is exactly its name (`alias("f")`);
//! - an attribute keeps it (`constructor`, `destructor`, `used`, `retain`),
//!   written out or through a macro the declaration's head names.
//!
//! # What is not judged
//!
//! A header's statics, a `static inline` function (the shape of a
//! configuration shim), one whose name a macro builds (`NS(alpha)(int)`),
//! and every static of a `.c` file that another file `#include`s, that
//! `#include`s a `.c` file, or that defines no function with external
//! linkage (a piece of a bundle another file includes). A file whose include
//! closure has a computed `#include` may see any header, so it is not judged
//! either. A single `.c` file scanned without `-d` has no closure to tell
//! it whether another file includes it.

use crate::analyze::context::{IncludeClosure, ProjectContext};
use crate::manifest::Severity;
use crate::rules::RuleViolation;
use crate::utility::cert_c::ast_utils::{
    declaration_has_storage_class, IdentifierBinding, ScopeDeclarations,
};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use tree_sitter::Node;

/// What the check reads of the project, taken from the context once per
/// file.
#[derive(Default)]
pub(super) struct ProjectTables {
    included_c_paths: Arc<HashSet<String>>,
    scanned_header_paths: Arc<HashSet<String>>,
    include_edges: Arc<HashMap<String, Vec<String>>>,
    include_edges_beyond_search_path: Arc<HashMap<String, Vec<String>>>,
    known_functions: Arc<HashSet<String>>,
    macro_names: HashSet<String>,
    /// `msc12_dead_callers`: a static only dead statics call is reported.
    dead_callers: bool,
}

impl ProjectTables {
    pub(super) fn of(context: &ProjectContext) -> Self {
        let mut macro_names: HashSet<String> = context.macro_definitions.keys().cloned().collect();
        macro_names.extend(context.function_macro_arms.keys().cloned());
        macro_names.extend(context.defined_macro_names.iter().cloned());
        ProjectTables {
            included_c_paths: Arc::clone(&context.included_c_paths),
            scanned_header_paths: Arc::clone(&context.scanned_header_paths),
            include_edges: Arc::clone(&context.include_edges),
            include_edges_beyond_search_path: Arc::clone(&context.include_edges_beyond_search_path),
            known_functions: Arc::clone(&context.known_functions),
            macro_names,
            dead_callers: context.settings.flag("msc12_dead_callers"),
        }
    }
}

/// One `static` function definition of the file.
struct Static<'a> {
    definition: Node<'a>,
    /// The name it defines; `None` when a macro builds it.
    ident: Option<Node<'a>>,
    name: Option<String>,
    /// Whether the check reports it: not `inline`, and named.
    judged: bool,
}

/// Report the file's uncalled statics into `violations`, and drop the
/// empty-body finding of each one reported: an uncalled static with an empty
/// body is reported once, as uncalled.
pub(super) fn check(
    root: &Node,
    source: &str,
    path: &str,
    tables: &ProjectTables,
    rule_id: &str,
    severity: Severity,
    violations: &mut Vec<RuleViolation>,
) {
    if path.is_empty() || !crate::files::is_c_translation_unit(path) {
        return;
    }
    let real = crate::analyze::compile_commands::real_path(Path::new(path));
    if tables.included_c_paths.contains(&real) {
        return;
    }
    let dead = crate::analyze::init_state::file_proven_dead_lines(source);
    let definitions = file_scope_definitions(root);
    if includes_c_file(root, source, &dead)
        || definitions
            .iter()
            .all(|d| declaration_has_storage_class(d, "static", source))
    {
        return;
    }
    let statics: Vec<Static> = definitions
        .iter()
        .filter(|d| declaration_has_storage_class(d, "static", source))
        .filter(|d| !crate::analyze::init_state::starts_in_dead_lines(d, &dead))
        .map(|d| {
            let ident = defined_name(d, source);
            let name = ident.and_then(|i| i.utf8_text(source.as_bytes()).ok().map(str::to_string));
            let judged = name.is_some() && !is_inline(d, source);
            Static {
                definition: *d,
                ident,
                name,
                judged,
            }
        })
        .collect();
    if !statics.iter().any(|s| s.judged) {
        return;
    }
    let names: HashSet<&str> = statics.iter().filter_map(|s| s.name.as_deref()).collect();
    let uses = FileUses::of(root, source, &names, &dead);

    // The text as written: the parse repair blanks a preprocessor arm a
    // construct is split across (an initializer whose entries differ by
    // `#ifdef`), and with it any use there. Same length and offsets.
    let raw = crate::analyze::noreturn::raw_text_or(path, source);
    let blanked = blank_comments_and_strings(&raw);
    let own_defines = defines(&blanked);
    let declared = declared_names(root, source);
    let unknown_macro_arguments =
        unknown_macro_arguments(&blanked, &own_defines, tables, &declared);

    // Live without a caller: what runs or may run whatever this file's
    // statics do.
    let mut live: HashSet<&str> = HashSet::new();
    for s in &statics {
        let Some(name) = s.name.as_deref() else {
            continue;
        };
        if !s.judged
            || uses.rooted.contains(name)
            || uses.retained.contains(name)
            || text_occurrences(&blanked, name) > uses.occurrences.get(name).copied().unwrap_or(0)
            || own_defines.iter().any(|d| d.pastes(name))
            || unknown_macro_arguments.iter().any(|a| pasted_from(name, a))
            || definition_is_retained(&s.definition, &raw, &blanked, &own_defines, tables)
            || uses.prototypes.get(name).is_some_and(|ps| {
                ps.iter()
                    .any(|p| prototype_is_retained(p, &raw, &blanked, &own_defines, tables))
            })
        {
            live.insert(name);
        }
    }
    // What the include closure sees, read only when something is left.
    if statics
        .iter()
        .any(|s| s.judged && s.name.as_deref().is_some_and(|n| !live.contains(n)))
    {
        match Closure::read(&real, &raw, &dead, tables) {
            None => return,
            Some(closure) => {
                for s in &statics {
                    if let Some(name) = s.name.as_deref() {
                        if closure.names(name) {
                            live.insert(name);
                        }
                    }
                }
            }
        }
    }
    // A static a live static uses is live. Without `msc12_dead_callers`, a
    // static any other static uses is: the rule's text reads "no caller".
    if !tables.dead_callers {
        for callees in uses.callees.values() {
            live.extend(callees.iter().copied());
        }
    }
    let mut work: Vec<&str> = live.iter().copied().collect();
    while let Some(caller) = work.pop() {
        if let Some(callees) = uses.callees.get(caller) {
            for &callee in callees {
                if live.insert(callee) {
                    work.push(callee);
                }
            }
        }
    }

    let mut reported: Vec<(usize, usize)> = Vec::new();
    for s in statics.iter().filter(|s| s.judged) {
        let (Some(name), Some(ident)) = (s.name.as_deref(), s.ident) else {
            continue;
        };
        if live.contains(name) {
            continue;
        }
        let mut callers: Vec<&str> = uses
            .callees
            .iter()
            .filter(|(caller, callees)| **caller != name && callees.contains(name))
            .map(|(caller, _)| *caller)
            .collect();
        callers.sort_unstable();
        let message = if callers.is_empty() {
            format!(
                "Static function '{name}' is never called and its address is never taken: it is code that is never executed."
            )
        } else {
            format!(
                "Static function '{name}' is called only from code that never runs ({}): it is never executed.",
                callers
                    .iter()
                    .map(|c| format!("'{c}'"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        violations.push(RuleViolation {
            rule_id: rule_id.to_string(),
            severity: severity.clone(),
            message,
            file_path: String::new(),
            line: ident.start_position().row + 1,
            column: ident.start_position().column + 1,
            suggestion: Some(format!(
                "Remove '{name}', or call it where it was meant to be called"
            )),
            ..Default::default()
        });
        reported.push((
            s.definition.start_position().row + 1,
            s.definition.start_position().column + 1,
        ));
    }
    if !reported.is_empty() {
        violations.retain(|v| {
            !(v.message.starts_with("Empty function body")
                && reported.contains(&(v.line, v.column)))
        });
    }
}

/// Whether the file `#include`s a `.c` file in an arm the file does not
/// prove dead: that file's code is part of this translation unit and may
/// call this file's statics (mbedtls's `psa_constant_names.c` includes the
/// generated `psa_constant_names_generated.c` that calls its own).
fn includes_c_file(root: &Node, source: &str, dead: &[(usize, usize)]) -> bool {
    lang_parsing_substrate::query::find_descendants_of_kind(*root, "preproc_include")
        .iter()
        .filter(|i| !crate::analyze::init_state::starts_in_dead_lines(i, dead))
        .filter_map(|i| i.child_by_field_name("path"))
        .filter_map(|p| p.utf8_text(source.as_bytes()).ok())
        .any(|p| {
            let p = p.trim_matches(|c| matches!(c, '"' | '<' | '>'));
            crate::files::is_c_translation_unit(p)
        })
}

/// Every function definition outside any function body: those at file
/// scope, through `#if` arms and other wrappers.
fn file_scope_definitions<'a>(root: &Node<'a>) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    let mut stack = vec![*root];
    while let Some(node) = stack.pop() {
        if node.kind() == "function_definition" {
            out.push(node);
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    out
}

/// Whether a definition carries `inline` (or `__inline`, `__inline__`).
fn is_inline(definition: &Node, source: &str) -> bool {
    let mut cursor = definition.walk();
    let inline = definition.children(&mut cursor).any(|c| {
        matches!(c.kind(), "storage_class_specifier" | "type_qualifier")
            && c.utf8_text(source.as_bytes())
                .is_ok_and(|t| matches!(t.trim(), "inline" | "__inline" | "__inline__"))
    });
    inline
}

/// The identifier a function definition defines: the innermost declarator
/// name under its `declarator` field. `None` when a function declarator's
/// own declarator is a function declarator: `static int NS(alpha)(int)`,
/// with `NS` a macro that builds the name, defines no function named `NS`.
fn defined_name<'a>(definition: &Node<'a>, source: &str) -> Option<Node<'a>> {
    let mut d = definition.child_by_field_name("declarator")?;
    loop {
        match d.kind() {
            // A keyword is no name: the parse misread a declaration
            // (`static WSD struct S { ... } s;` with WSD unexpanded).
            "identifier" => {
                return (!d.utf8_text(source.as_bytes()).is_ok_and(is_keyword)).then_some(d)
            }
            "function_declarator" => {
                let inner = d.child_by_field_name("declarator")?;
                if inner.kind() == "function_declarator" {
                    return None;
                }
                d = inner;
            }
            "pointer_declarator" | "parenthesized_declarator" | "attributed_declarator" => {
                d = d
                    .child_by_field_name("declarator")
                    .or_else(|| d.named_child(0))?;
            }
            _ => return None,
        }
    }
}

/// Whether `word` is a C keyword.
fn is_keyword(word: &str) -> bool {
    const KEYWORDS: [&str; 34] = [
        "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else",
        "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long", "register",
        "restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef",
        "union", "unsigned", "void", "volatile", "while",
    ];
    KEYWORDS.contains(&word)
}

/// What one walk of a file's tree finds about the names of its statics.
struct FileUses<'n, 't> {
    /// Names some use reaches from code that runs whatever the statics do:
    /// a use at file scope, or in a function that is not one of the file's
    /// statics.
    rooted: HashSet<&'n str>,
    /// For each static, by name, the statics its body uses (itself excluded).
    callees: HashMap<&'n str, HashSet<&'n str>>,
    /// Names a string in an attribute spells exactly (`alias("f")`).
    retained: HashSet<&'n str>,
    /// Each name's file-scope prototypes, whose attributes may keep it.
    prototypes: HashMap<&'n str, Vec<Node<'t>>>,
    /// How often each name occurs in the tree as any identifier.
    occurrences: HashMap<&'n str, usize>,
}

impl<'n, 't> FileUses<'n, 't> {
    fn of(
        root: &Node<'t>,
        source: &str,
        names: &HashSet<&'n str>,
        dead: &[(usize, usize)],
    ) -> Self {
        let mut uses = FileUses {
            rooted: HashSet::new(),
            callees: HashMap::new(),
            retained: HashSet::new(),
            prototypes: HashMap::new(),
            occurrences: HashMap::new(),
        };
        let scopes = ScopeDeclarations::default();
        let mut stack = vec![*root];
        while let Some(node) = stack.pop() {
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor));
            let kind = node.kind();
            let text = || node.utf8_text(source.as_bytes()).unwrap_or("");
            if kind == "string_content" {
                if let Some(n) = names.get(text()) {
                    if inside_attribute(&node) {
                        uses.retained.insert(n);
                    }
                }
                continue;
            }
            if !matches!(
                kind,
                "identifier" | "type_identifier" | "field_identifier" | "statement_identifier"
            ) {
                continue;
            }
            let Some(&name) = names.get(text()) else {
                continue;
            };
            *uses.occurrences.entry(name).or_default() += 1;
            // A member or a label lives in a namespace of its own. A type
            // name cannot share the function's file-scope name, so one
            // spelled like it is the parse misreading a use of it.
            if !matches!(kind, "identifier" | "type_identifier") {
                continue;
            }
            // A prototype or a definition names the function without using
            // it. A "prototype" in a block is the parse misreading a call
            // (`f(x);` after a macro it cannot expand), so it falls through
            // to resolution, where it reads as a use.
            if let Some(declaration) = declared_function(&node)
                .filter(|d| d.kind() == "function_definition" || !in_block(d))
            {
                if declaration.kind() == "declaration" {
                    uses.prototypes.entry(name).or_default().push(declaration);
                }
                continue;
            }
            if crate::analyze::init_state::starts_in_dead_lines(&node, dead) {
                continue;
            }
            let used = if kind == "type_identifier" {
                true
            } else if let Some(definition_parameter) = parameter_of_definition(&node) {
                // A parameter a definition declares hides the function in
                // that body. A prototype's parameter names nothing outside
                // it, so a "prototype" parameter spelled like the function is
                // the parse misreading a call that passes it by name: a
                // code-generating macro at file scope (`ph_gen(, heap, T,
                // link, cmp_fn)`), or `atexit(fn);` after a macro the parse
                // cannot expand.
                !definition_parameter
            } else {
                !matches!(
                    scopes.resolve_identifier_binding(&node, name, source),
                    Some(IdentifierBinding::Parameter(_))
                ) && !matches!(
                    scopes.resolve_identifier_binding(&node, name, source),
                    Some(IdentifierBinding::Local(decl)) if declares_block_object(&decl, name, source)
                )
            };
            if !used {
                continue;
            }
            match enclosing_function(&node, source) {
                Enclosing::Static(caller) => {
                    if let Some(&caller) = names.get(caller.as_str()) {
                        if caller != name {
                            uses.callees.entry(caller).or_default().insert(name);
                        }
                    } else {
                        uses.rooted.insert(name);
                    }
                }
                Enclosing::Other => {
                    uses.rooted.insert(name);
                }
            }
        }
        uses
    }
}

/// The function a use sits in, for the call graph among the file's statics.
enum Enclosing {
    /// A `static` function definition, by the name it defines.
    Static(String),
    /// File scope, a function with external linkage, or a static whose name
    /// a macro builds: code that runs whatever the file's statics do.
    Other,
}

fn enclosing_function(node: &Node, source: &str) -> Enclosing {
    let mut n = *node;
    while let Some(parent) = n.parent() {
        if parent.kind() == "function_definition" {
            if !declaration_has_storage_class(&parent, "static", source) {
                return Enclosing::Other;
            }
            return defined_name(&parent, source)
                .and_then(|i| i.utf8_text(source.as_bytes()).ok())
                .map_or(Enclosing::Other, |name| Enclosing::Static(name.to_string()));
        }
        n = parent;
    }
    Enclosing::Other
}

/// The declaration or definition `ident` names a function in, when `ident`
/// is the name a function declarator declares there.
fn declared_function<'a>(ident: &Node<'a>) -> Option<Node<'a>> {
    let mut child = *ident;
    let mut parent = child.parent()?;
    while matches!(
        parent.kind(),
        "parenthesized_declarator" | "attributed_declarator"
    ) {
        child = parent;
        parent = parent.parent()?;
    }
    if parent.kind() != "function_declarator"
        || parent.child_by_field_name("declarator") != Some(child)
    {
        return None;
    }
    let mut n = parent;
    loop {
        match n.kind() {
            "declaration" | "function_definition" => return Some(n),
            "pointer_declarator"
            | "function_declarator"
            | "init_declarator"
            | "parenthesized_declarator"
            | "attributed_declarator" => n = n.parent()?,
            _ => return None,
        }
    }
}

/// Whether `node` lies inside a block.
fn in_block(node: &Node) -> bool {
    let mut n = *node;
    while let Some(parent) = n.parent() {
        if parent.kind() == "compound_statement" {
            return true;
        }
        n = parent;
    }
    false
}

/// Whether `decl`, the declaration an occurrence of `name` resolves to,
/// declares an object of that name in a block, hiding the function. The
/// resolver also answers with a file-scope prototype, and a prototype in a
/// block names the file-scope function: neither hides it.
fn declares_block_object(decl: &Node, name: &str, source: &str) -> bool {
    if !in_block(decl) {
        return false;
    }
    let mut cursor = decl.walk();
    let declarators: Vec<Node> = decl
        .children_by_field_name("declarator", &mut cursor)
        .collect();
    !declarators.iter().any(|d| {
        let mut stack = vec![*d];
        let mut function = false;
        while let Some(x) = stack.pop() {
            match x.kind() {
                "function_declarator" => {
                    function = true;
                    if let Some(inner) = x.child_by_field_name("declarator") {
                        stack.push(inner);
                    }
                }
                "identifier" => {
                    return function && x.utf8_text(source.as_bytes()).ok() == Some(name);
                }
                "pointer_declarator"
                | "parenthesized_declarator"
                | "init_declarator"
                | "attributed_declarator"
                | "array_declarator" => {
                    if let Some(inner) = x
                        .child_by_field_name("declarator")
                        .or_else(|| x.named_child(0))
                    {
                        stack.push(inner);
                    }
                }
                _ => {}
            }
        }
        false
    })
}

/// When `ident` is the name a parameter declaration declares: whether that
/// parameter list is a function definition's, rather than a prototype's.
/// `None` when `ident` declares no parameter.
fn parameter_of_definition(ident: &Node) -> Option<bool> {
    let mut n = *ident;
    let mut parameter = None;
    while let Some(parent) = n.parent() {
        match parent.kind() {
            "pointer_declarator"
            | "parenthesized_declarator"
            | "array_declarator"
            | "attributed_declarator"
            | "function_declarator"
                if parameter.is_none() =>
            {
                n = parent;
            }
            "parameter_declaration" if parameter.is_none() => {
                if parent.child_by_field_name("declarator") != Some(n) {
                    return None;
                }
                parameter = Some(parent);
                n = parent;
            }
            "parameter_list"
            | "function_declarator"
            | "pointer_declarator"
            | "parenthesized_declarator"
            | "attributed_declarator"
                if parameter.is_some() =>
            {
                n = parent;
            }
            "function_definition" if parameter.is_some() => {
                return Some(parent.child_by_field_name("declarator") == Some(n));
            }
            _ => return parameter.map(|_| false),
        }
    }
    parameter.map(|_| false)
}

/// Whether `node` is inside an attribute (`__attribute__((...))`, `[[...]]`,
/// `__declspec(...)`).
fn inside_attribute(node: &Node) -> bool {
    let mut n = *node;
    while let Some(parent) = n.parent() {
        match parent.kind() {
            "attribute_specifier" | "attribute_declaration" | "ms_declspec_modifier" => {
                return true
            }
            "compound_statement" | "translation_unit" => return false,
            _ => n = parent,
        }
    }
    false
}

/// The attribute nodes of a declaration's head: its own, and those its
/// declarators carry, never inside a parameter list or the body.
fn head_parts<'a>(declaration: &Node<'a>) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    let mut stack = vec![*declaration];
    while let Some(n) = stack.pop() {
        let mut cursor = n.walk();
        for c in n.children(&mut cursor) {
            match c.kind() {
                "compound_statement" | "parameter_list" => {}
                _ => {
                    out.push(c);
                    stack.push(c);
                }
            }
        }
    }
    out
}

/// The toolchain's keep-alive attributes, by the words that spell them.
const KEEP_WORDS: [&str; 6] = [
    "constructor",
    "destructor",
    "used",
    "__used__",
    "retain",
    "__retain__",
];

/// Whether an attribute written out in the declaration's head keeps the
/// function (`__attribute__((constructor))`, `[[gnu::used]]`).
fn attributes_keep(declaration: &Node, source: &str) -> bool {
    head_parts(declaration)
        .iter()
        .filter(|n| {
            matches!(
                n.kind(),
                "attribute_specifier" | "attribute_declaration" | "ms_declspec_modifier"
            )
        })
        .filter_map(|n| n.utf8_text(source.as_bytes()).ok())
        .any(|t| KEEP_WORDS.iter().any(|w| text_occurrences(t, w) > 0))
}

/// Whether a keep-alive attribute applies to the definition: written out,
/// or through a macro its head names (`#define CONSTRUCTOR
/// __attribute__((constructor))`), read from this file's `#define`s, or,
/// for a macro nothing the scan read defines, from a name that spells one
/// (`__attribute_used__`, `ATTRIBUTE_USED`).
fn definition_is_retained(
    definition: &Node,
    raw: &str,
    blanked: &str,
    own_defines: &[Define],
    tables: &ProjectTables,
) -> bool {
    if attributes_keep(definition, raw) {
        return true;
    }
    // The head as written, from the end of the item before the definition to
    // its name: the parse repair blanks a macro it cannot expand in front of a
    // storage class, which leaves it outside the definition's node.
    let start = definition.prev_sibling().map_or(0, |p| p.end_byte());
    let end = defined_name(definition, raw)
        .map(|n| n.start_byte())
        .or_else(|| {
            definition
                .child_by_field_name("body")
                .map(|b| b.start_byte())
        })
        .unwrap_or(definition.end_byte());
    let Some(head) = blanked.get(start..end) else {
        return false;
    };
    identifiers(head)
        .into_iter()
        .any(|word| KEEP_WORDS.contains(&word) || macro_keeps(word, own_defines, tables, 0))
}

/// Whether a keep-alive attribute applies to a prototype: written out, or
/// through a macro it names outside its parameter list
/// (`static void f(void) CONSTRUCTOR;`).
fn prototype_is_retained(
    prototype: &Node,
    raw: &str,
    blanked: &str,
    own_defines: &[Define],
    tables: &ProjectTables,
) -> bool {
    if attributes_keep(prototype, raw) {
        return true;
    }
    let mut text = blanked
        .get(prototype.start_byte()..prototype.end_byte())
        .unwrap_or("")
        .to_string();
    // The parameters' names are no attributes (`unsigned long used`).
    for list in
        lang_parsing_substrate::query::find_descendants_of_kind(*prototype, "parameter_list")
    {
        let from = list.start_byte() - prototype.start_byte();
        let to = list.end_byte() - prototype.start_byte();
        if text.is_char_boundary(from) && text.is_char_boundary(to) && to <= text.len() {
            text.replace_range(from..to, &" ".repeat(to - from));
        }
    }
    identifiers(&text)
        .into_iter()
        .any(|word| KEEP_WORDS.contains(&word) || macro_keeps(word, own_defines, tables, 0))
}

fn macro_keeps(name: &str, own_defines: &[Define], tables: &ProjectTables, depth: usize) -> bool {
    let bodies: Vec<&Define> = own_defines.iter().filter(|d| d.name == name).collect();
    if bodies.is_empty() {
        if tables.macro_names.contains(name) {
            // Defined in another file: read its spelling as below.
        } else if !name.chars().any(|c| c.is_ascii_uppercase()) && !name.starts_with("__") {
            // An ordinary type or object name, not a macro.
            return false;
        }
        let lower = name.to_ascii_lowercase();
        return (lower.contains("used") && !lower.contains("unused"))
            || lower.contains("constructor")
            || lower.contains("destructor")
            || lower.contains("retain");
    }
    bodies.iter().any(|d| {
        KEEP_WORDS.iter().any(|w| text_occurrences(&d.body, w) > 0)
            || (depth < 4
                && identifiers(&d.body)
                    .into_iter()
                    .any(|i| i != name && macro_keeps(i, own_defines, tables, depth + 1)))
    })
}

/// One `#define` of a file.
struct Define {
    name: String,
    params: Vec<String>,
    body: String,
}

impl Define {
    /// Whether the body pastes with `##` a literal fragment `name` begins or
    /// ends with, so an expansion may spell it. A parameter is the
    /// invocation's argument, not a fragment.
    fn pastes(&self, name: &str) -> bool {
        let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
        let literal = |w: &str| !w.is_empty() && !self.params.iter().any(|p| p == w);
        self.body.match_indices("##").any(|(at, _)| {
            let left = self.body[..at].trim_end();
            let start = left
                .char_indices()
                .rev()
                .take_while(|(_, c)| ident(*c))
                .last()
                .map_or(left.len(), |(i, _)| i);
            let left_word = &left[start..];
            let right = self.body[at + 2..].trim_start();
            let right_word: String = right.chars().take_while(|c| ident(*c)).collect();
            (literal(left_word) && name.starts_with(left_word))
                || (literal(&right_word) && name.ends_with(&right_word))
        })
    }
}

/// The `#define`s of `blanked` (a file with its comments and strings
/// blanked), each `\`-continued definition one.
fn defines(blanked: &str) -> Vec<Define> {
    let mut out = Vec::new();
    let mut lines = blanked.lines();
    while let Some(line) = lines.next() {
        let Some(rest) = line.trim_start().strip_prefix('#') else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix("define") else {
            continue;
        };
        if !rest.starts_with([' ', '\t']) {
            continue;
        }
        let mut logical = rest.trim_start().to_string();
        while logical.trim_end().ends_with('\\') {
            let keep = logical.trim_end().len() - 1;
            logical.truncate(keep);
            match lines.next() {
                Some(next) => {
                    logical.push(' ');
                    logical.push_str(next);
                }
                None => break,
            }
        }
        let name_end = logical
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(logical.len());
        let name = logical[..name_end].to_string();
        if name.is_empty() {
            continue;
        }
        let after = &logical[name_end..];
        let (params, body) = match after.strip_prefix('(') {
            Some(list) => match list.find(')') {
                Some(close) => (
                    identifiers(&list[..close])
                        .into_iter()
                        .map(str::to_string)
                        .collect(),
                    list[close + 1..].to_string(),
                ),
                None => continue,
            },
            None => (Vec::new(), after.to_string()),
        };
        out.push(Define { name, params, body });
    }
    out
}

/// The identifiers `text` spells, in order.
fn identifiers(text: &str) -> Vec<&str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| w.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'))
        .collect()
}

/// Words that are not macros when followed by `(`.
const NOT_MACROS: [&str; 18] = [
    "if",
    "while",
    "for",
    "switch",
    "return",
    "sizeof",
    "_Alignof",
    "alignof",
    "__attribute__",
    "__typeof__",
    "typeof",
    "_Generic",
    "defined",
    "__asm__",
    "asm",
    "__declspec",
    "_Static_assert",
    "static_assert",
];

/// The names the file declares: every identifier a declarator declares
/// (objects, functions, parameters, typedefs), wherever it is.
fn declared_names<'s>(root: &Node, source: &'s str) -> HashSet<&'s str> {
    let mut out = HashSet::new();
    let mut stack = vec![*root];
    while let Some(node) = stack.pop() {
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
        if node.kind() != "identifier" {
            continue;
        }
        let declares = node.parent().is_some_and(|p| {
            matches!(
                p.kind(),
                "init_declarator"
                    | "parameter_declaration"
                    | "pointer_declarator"
                    | "array_declarator"
                    | "function_declarator"
                    | "parenthesized_declarator"
                    | "declaration"
                    | "type_definition"
            ) && p.child_by_field_name("declarator") == Some(node)
        });
        if declares {
            if let Ok(text) = node.utf8_text(source.as_bytes()) {
                out.insert(text);
            }
        }
    }
    out
}

/// The bare-identifier arguments of the invocations, in `blanked`, of a
/// function-like name that nothing the scan read defines or declares: a
/// macro from a header the scan cannot see, whose expansion may paste its
/// arguments into names (`G_DEFINE_TYPE(Foo, foo, G_TYPE_OBJECT)` defines and
/// uses `foo_init`). At file scope, where such generators are invoked, every
/// such argument; in a function body, where an unknown name is far more
/// often a library function, only an argument that names nothing the file
/// declares (`snprintf(buf, n, fmt, name)` passes the local `name`).
fn unknown_macro_arguments<'b>(
    blanked: &'b str,
    own_defines: &[Define],
    tables: &ProjectTables,
    declared: &HashSet<&str>,
) -> Vec<&'b str> {
    let own: HashSet<&str> = own_defines.iter().map(|d| d.name.as_str()).collect();
    let bytes = blanked.as_bytes();
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut out = Vec::new();
    // Brace depth before each byte: 0 at file scope.
    let mut depth_at = vec![0usize; bytes.len() + 1];
    let mut braces = 0usize;
    for (k, &b) in bytes.iter().enumerate() {
        match b {
            b'{' => braces += 1,
            b'}' => braces = braces.saturating_sub(1),
            _ => {}
        }
        depth_at[k + 1] = braces;
    }
    let mut i = 0;
    while i < bytes.len() {
        if !(bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') || (i > 0 && ident(bytes[i - 1])) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && ident(bytes[i]) {
            i += 1;
        }
        let word = &blanked[start..i];
        let mut j = i;
        while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
            j += 1;
        }
        if j >= bytes.len()
            || bytes[j] != b'('
            || NOT_MACROS.contains(&word)
            || word.starts_with("__builtin")
            || own.contains(word)
            || tables.macro_names.contains(word)
            || tables.known_functions.contains(word)
        {
            continue;
        }
        // The arguments at depth one, up to the matching `)`.
        let mut depth = 0usize;
        let mut k = j;
        let mut arg_start = j + 1;
        while k < bytes.len() {
            match bytes[k] {
                b'(' => depth += 1,
                b')' | b',' if depth == 1 => {
                    let arg = blanked[arg_start..k].trim();
                    if !arg.is_empty()
                        && arg.bytes().all(ident)
                        && !arg.as_bytes()[0].is_ascii_digit()
                        && (depth_at[start] == 0 || !declared.contains(arg))
                    {
                        out.push(arg);
                    }
                    arg_start = k + 1;
                    if bytes[k] == b')' {
                        break;
                    }
                }
                b')' => depth -= 1,
                _ => {}
            }
            k += 1;
        }
    }
    out
}

/// Whether a macro handed `argument` may paste `name` from it: the whole
/// name, or a prefix or suffix of it at a `_` boundary.
fn pasted_from(name: &str, argument: &str) -> bool {
    name == argument
        || name
            .strip_prefix(argument)
            .is_some_and(|rest| rest.starts_with('_'))
        || name
            .strip_suffix(argument)
            .is_some_and(|rest| rest.ends_with('_'))
}

/// The files the file's translation unit includes, as text with comments and
/// strings blanked, and their `#define`s.
struct Closure {
    texts: Vec<(String, Vec<Define>)>,
}

impl Closure {
    /// The include closure of the file at `real` (a real path, whose text
    /// is `raw`): the files its includes resolve to, the scanned headers an
    /// unresolved spelling may name, and the files its own quoted
    /// `#include` lines name beside it, which the include graph misses where
    /// the parse does not read the directive as one (an X-macro list
    /// included inside an initializer). `None` when a computed `#include`
    /// may name any header, so no use can be ruled out.
    fn read(
        real: &str,
        raw: &str,
        dead: &[(usize, usize)],
        tables: &ProjectTables,
    ) -> Option<Closure> {
        let layers = [
            tables.include_edges.as_ref(),
            tables.include_edges_beyond_search_path.as_ref(),
        ];
        let closure = IncludeClosure::of_layers(&layers, Path::new(real));
        if closure.as_ref().is_some_and(|c| c.any) {
            return None;
        }
        let mut paths: Vec<String> = Vec::new();
        if let Some(closure) = &closure {
            paths.extend(closure.files.iter().filter(|p| *p != real).cloned());
            if !closure.unresolved.is_empty() {
                paths.extend(
                    tables
                        .scanned_header_paths
                        .iter()
                        .filter(|h| !closure.files.contains(*h) && closure.may_include(h))
                        .cloned(),
                );
            }
        }
        if let Some(dir) = Path::new(real).parent() {
            for (row, line) in raw.lines().enumerate() {
                let number = row + 1;
                if dead.iter().any(|&(s, e)| (s..=e).contains(&number)) {
                    continue;
                }
                let Some(spelling) = quoted_include(line) else {
                    continue;
                };
                let beside = dir.join(spelling);
                if beside.is_file() {
                    let path = crate::analyze::compile_commands::real_path(&beside);
                    if path != real && !paths.contains(&path) {
                        paths.push(path);
                    }
                }
            }
        }
        let texts = paths
            .into_iter()
            .filter_map(|p| std::fs::read_to_string(p).ok())
            .map(|text| {
                let blanked = blank_comments_and_strings(&text);
                let defines = defines(&blanked);
                (blanked, defines)
            })
            .collect();
        Some(Closure { texts })
    }

    /// Whether a file of the closure spells `name`, or pastes it.
    fn names(&self, name: &str) -> bool {
        self.texts.iter().any(|(text, defines)| {
            text_occurrences(text, name) > 0 || defines.iter().any(|d| d.pastes(name))
        })
    }
}

/// The spelling of a quoted `#include` on `line`, if it is one.
fn quoted_include(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix('#')?.trim_start();
    let rest = rest.strip_prefix("include")?.trim_start();
    let rest = rest.strip_prefix('"')?;
    rest.find('"').map(|end| &rest[..end])
}

/// `source` with every comment, string literal and character constant
/// replaced by spaces, newlines kept. A `'` right after a digit is a C23
/// digit separator (`1'000`), not a character constant.
fn blank_comments_and_strings(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for b in &mut out[from..to] {
            if *b != b'\n' {
                *b = b' ';
            }
        }
    };
    while i < bytes.len() {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                let end = source[i..].find('\n').map_or(bytes.len(), |e| i + e);
                blank(&mut out, i, end);
                i = end;
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let end = source[i + 2..]
                    .find("*/")
                    .map_or(bytes.len(), |e| i + 2 + e + 2);
                blank(&mut out, i, end);
                i = end;
            }
            b'\'' if i > 0 && bytes[i - 1].is_ascii_digit() => i += 1,
            q @ (b'"' | b'\'') => {
                let mut j = i + 1;
                while j < bytes.len() && bytes[j] != q && bytes[j] != b'\n' {
                    j += if bytes[j] == b'\\' { 2 } else { 1 };
                }
                let end = (j + 1).min(bytes.len());
                blank(&mut out, i, end);
                i = end;
            }
            _ => i += 1,
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

/// How often `word` occurs in `text` as a whole identifier.
fn text_occurrences(text: &str, word: &str) -> usize {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(word)
        .filter(|(at, _)| {
            !text[..*at].chars().next_back().is_some_and(ident)
                && !text[at + word.len()..].chars().next().is_some_and(ident)
        })
        .count()
}
