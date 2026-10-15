//! Objects a macro's expansion declares at file scope.
//!
//! `SQLITE_EXTENSION_INIT1` on a line of its own declares `sqlite3_api` once
//! the preprocessor expands it, and `DECLARE_PTR(struct conn, g);` declares
//! `g`; the parser sees neither declaration. A file's prescan records each
//! identifier that begins a file-scope item, with the argument list after it
//! ([`FileScopeMacroItem`]); once every scanned file's and resolved header's
//! `#define`s are known, [`declare_macro_objects`] expands each item that
//! names a macro and parses the expansion. An expansion that parses to
//! nothing but declarations declares their objects, with the file and the
//! linkage each has ([`MacroDeclaredObject`]); what does not parse as
//! declarations declares nothing (ADR-0006).

use crate::analyze::check_macros::MacroDefinition;
use crate::analyze::context::ProjectContext;
use crate::utility::cert_c::ast_utils;
use crate::utility::cert_c::pp_tokens::{lex_replacement_list, PpKind};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

/// One identifier that begins a file-scope item, and the argument list after
/// it when one follows: a candidate invocation of a declaring macro.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FileScopeMacroItem {
    /// The file the item is in, as `compile_commands::real_path` spells it.
    pub file: String,
    /// The identifier the item begins with.
    pub name: String,
    /// The argument texts of the parenthesized list after it, if any.
    pub args: Option<Vec<String>>,
}

/// The linkage a macro-declared object has where it is declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Linkage {
    /// `static`: an object of that file alone.
    Internal,
    /// A definition with external linkage: any translation unit may name it.
    External,
    /// An `extern` declaration: the object is defined elsewhere.
    Extern,
}

/// One declaration a macro's expansion makes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct MacroDeclaredObject {
    /// The file the invocation is in.
    pub file: String,
    /// The linkage the declaration gives the object.
    pub linkage: Linkage,
}

/// How far past an item's first character its argument list is read.
const INVOCATION_WINDOW: usize = 4096;

/// The identifiers that begin a file-scope item of `root` outside a function
/// body or a directive, with the argument list after each when one follows.
/// Every such item is kept, a declaration that starts with a type name
/// included: whether its first word is a macro is known only once every
/// file's `#define`s are. A function definition is one too: the parser reads
/// an invocation on the line before it (`DECL_LOG` then `static void f()`)
/// as the start of the definition.
pub fn file_scope_macro_items(root: &Node, source: &str, file: &str) -> Vec<FileScopeMacroItem> {
    let mut out: Vec<FileScopeMacroItem> = Vec::new();
    let mut stack = vec![*root];
    while let Some(scope) = stack.pop() {
        let mut cursor = scope.walk();
        let children: Vec<Node> = scope.children(&mut cursor).collect();
        for child in children {
            match child.kind() {
                "preproc_function_def"
                | "preproc_def"
                | "preproc_include"
                | "preproc_call"
                | "comment" => {}
                k if k.starts_with("preproc_")
                    || matches!(k, "ERROR" | "linkage_specification" | "declaration_list") =>
                {
                    stack.push(child);
                    if k == "ERROR" {
                        out.extend(items_in(&child, source, file));
                    }
                }
                _ => out.extend(items_in(&child, source, file)),
            }
        }
    }
    let mut seen = HashSet::new();
    out.retain(|item| seen.insert(item.clone()));
    out
}

/// The items `node` holds at file scope: the one it begins with, and one for
/// each later line it spans that begins outside any brace, bracket or
/// parenthesis of it. The parser folds invocations on lines of their own into
/// the item that follows (`DECL_A` / `DECL_B` / `int x;` is one declaration
/// to it), so each line's first word is an item start; a line inside a struct
/// body, an initializer or a function body is not.
fn items_in(node: &Node, source: &str, file: &str) -> Vec<FileScopeMacroItem> {
    let end = node
        .child_by_field_name("body")
        .map_or(node.end_byte(), |body| body.start_byte());
    let mut starts = vec![node.start_byte()];
    let text = source.get(node.start_byte()..end).unwrap_or("");
    starts.extend(
        text.match_indices('\n')
            .map(|(i, _)| node.start_byte() + i + 1)
            .map(|line| {
                line + source.get(line..end).map_or(0, |rest| {
                    rest.len() - rest.trim_start_matches([' ', '\t']).len()
                })
            })
            .filter(|&at| at < end && !nested_in(node, at)),
    );
    starts
        .into_iter()
        .filter_map(|at| item_at(at, source, file))
        .collect()
}

/// Whether byte `at` lies inside a bracketed part of `item`.
fn nested_in(item: &Node, at: usize) -> bool {
    let mut current = item.descendant_for_byte_range(at, at);
    while let Some(n) = current.filter(|n| n.id() != item.id()) {
        if matches!(
            n.kind(),
            "field_declaration_list"
                | "compound_statement"
                | "initializer_list"
                | "enumerator_list"
                | "argument_list"
                | "parameter_list"
                | "parenthesized_expression"
        ) {
            return true;
        }
        current = n.parent();
    }
    false
}

/// The identifier at byte `at`, and the argument list after it.
fn item_at(at: usize, source: &str, file: &str) -> Option<FileScopeMacroItem> {
    let text = source.get(at..)?;
    let name: String = text
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty()
        || name.starts_with(|c: char| c.is_ascii_digit())
        || ast_utils::is_c_keyword(&name)
    {
        return None;
    }
    let chars: Vec<char> = text.chars().take(INVOCATION_WINDOW).collect();
    let args = chars
        .iter()
        .skip(name.len())
        .position(|c| !c.is_whitespace())
        .map(|p| p + name.len())
        .filter(|&i| chars.get(i) == Some(&'('))
        .and_then(|open| crate::analyze::macro_expand::parse_call_args(&chars, open))
        .map(|(args, _)| args);
    Some(FileScopeMacroItem {
        file: file.to_string(),
        name,
        args,
    })
}

/// Expand every item of `context.file_scope_macro_items` that names a macro
/// through each of its definitions, and file the objects the declarations it
/// stands for declare in `macro_declared_objects` and `global_object_names`.
/// Run again whenever `macro_definitions` grows: it starts over from the
/// items, so a second run adds what new definitions declare.
pub fn declare_macro_objects(context: &mut ProjectContext) {
    let mut declared: HashMap<String, Vec<MacroDeclaredObject>> = HashMap::new();
    for item in context.file_scope_macro_items.iter() {
        let Some(definitions) = context.macro_definitions.get(&item.name) else {
            continue;
        };
        for definition in definitions {
            let Some(text) = expansion(definition, item.args.as_deref()) else {
                continue;
            };
            for (name, linkage) in declarations_in(&text) {
                let slot = declared.entry(name).or_default();
                let object = MacroDeclaredObject {
                    file: item.file.clone(),
                    linkage,
                };
                if !slot.contains(&object) {
                    slot.push(object);
                }
            }
        }
    }
    Arc::make_mut(&mut context.global_object_names).extend(declared.keys().cloned());
    context.macro_declared_objects = Arc::new(declared);
}

/// The replacement `definition` gives an invocation with `args` (none for an
/// object-like macro), its parameters replaced token by token. `None` for a
/// definition that cannot be read, or an argument count that does not match.
fn expansion(definition: &MacroDefinition, args: Option<&[String]>) -> Option<String> {
    match definition {
        MacroDefinition::Object { body } => Some(body.clone()),
        MacroDefinition::Function { params, body } => {
            let args =
                args.filter(|a| a.len() == params.len() || (params.is_empty() && a.len() <= 1))?;
            let tokens = lex_replacement_list(body, true);
            Some(
                tokens
                    .iter()
                    .map(|t| {
                        let replaced = (t.kind == PpKind::Identifier)
                            .then(|| params.iter().position(|p| *p == t.text))
                            .flatten()
                            .and_then(|i| args.get(i));
                        replaced.map_or_else(|| t.text.to_string(), Clone::clone)
                    })
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        }
        MacroDefinition::Opaque => None,
    }
}

/// The objects `text` declares, when it parses as declarations and nothing
/// else, with the linkage each has.
fn declarations_in(text: &str) -> Vec<(String, Linkage)> {
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&crate::parser::c_language()).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(text, None) else {
        return Vec::new();
    };
    let root = tree.root_node();
    let declarations: Vec<Node> = root.named_children(&mut root.walk()).collect();
    if root.has_error()
        || declarations.is_empty()
        || declarations.iter().any(|d| d.kind() != "declaration")
    {
        return Vec::new();
    }
    let mut out = Vec::new();
    for declaration in declarations {
        let linkage = if ast_utils::declaration_has_storage_class(&declaration, "static", text) {
            Linkage::Internal
        } else if ast_utils::declaration_has_storage_class(&declaration, "extern", text) {
            Linkage::Extern
        } else {
            Linkage::External
        };
        for declarator in declaration.children_by_field_name("declarator", &mut declaration.walk())
        {
            let declarator = if declarator.kind() == "init_declarator" {
                declarator
                    .child_by_field_name("declarator")
                    .unwrap_or(declarator)
            } else {
                declarator
            };
            if lang_parsing_substrate::query::find_first_descendant(declarator, |n| {
                n.kind() == "function_declarator"
            })
            .is_some()
                || declarator.kind() == "function_declarator"
            {
                continue;
            }
            let name = ast_utils::get_identifier_from_declarator(&declarator, text);
            if !name.is_empty() {
                out.push((name, linkage));
            }
        }
    }
    out
}
