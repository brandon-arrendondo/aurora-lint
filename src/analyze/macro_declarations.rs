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
//! linkage each has ([`MacroDeclaredObject`]), and a typedef among them
//! declares its name in the file of the invocation
//! (`DECLARE_HANDLE(HWND);`); what does not parse as declarations declares
//! nothing (ADR-0006).

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
    let mut typedefs: HashMap<String, HashSet<String>> = HashMap::new();
    for item in context.file_scope_macro_items.iter() {
        for text in typedef_expansions(context, &item.name, item.args.as_deref()) {
            let names = typedef_names_in(&text);
            if !names.is_empty() {
                typedefs.entry(item.file.clone()).or_default().extend(names);
            }
        }
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
    context.macro_declared_typedef_names = Arc::new(typedefs);
}

/// How many invocations nested in an expansion [`typedef_expansions`]
/// expands in turn before it stops: a macro whose expansion invokes itself
/// stops here, and its text then parses as no typedef.
const MAX_NESTED_EXPANSIONS: usize = 8;

/// How many texts one invocation may expand to, each nested invocation
/// with several definitions multiplying them.
const MAX_EXPANSION_TEXTS: usize = 16;

/// Every text the invocation `name(args)` expands to, through each
/// definition of `name` and of every function-like macro its expansion
/// invokes in turn (`OUTER(n)` as `INNER(n)` as `typedef int n`), `##`
/// pastes joined, the pasting definitions
/// ([`ProjectContext::pasting_macro_definitions`]) included. Only the
/// typedef names an expansion declares are read from these: the objects
/// [`declare_macro_objects`] files come from the definitions it read
/// before, so what other rules see of a macro's declarations is unchanged.
fn typedef_expansions(
    context: &ProjectContext,
    name: &str,
    args: Option<&[String]>,
) -> Vec<String> {
    let mut out = Vec::new();
    for definition in definitions_of(context, name) {
        if let Some(text) = expansion(definition, args) {
            rescan(context, text, 0, &mut out);
        }
    }
    out
}

/// Every definition of `name`, those that paste tokens included.
fn definitions_of<'a>(
    context: &'a ProjectContext,
    name: &str,
) -> impl Iterator<Item = &'a MacroDefinition> {
    context
        .macro_definitions
        .get(name)
        .into_iter()
        .flatten()
        .chain(
            context
                .pasting_macro_definitions
                .get(name)
                .into_iter()
                .flatten(),
        )
}

/// File `text` in `out` once the first function-like invocation in it is
/// expanded, through each of that macro's definitions and again for the
/// invocations each expansion leaves; `text` as it is when it invokes none,
/// or once [`MAX_NESTED_EXPANSIONS`] are spent.
fn rescan(context: &ProjectContext, text: String, depth: usize, out: &mut Vec<String>) {
    if out.len() >= MAX_EXPANSION_TEXTS {
        return;
    }
    let invocation = (depth < MAX_NESTED_EXPANSIONS)
        .then(|| nested_invocation(context, &text))
        .flatten();
    let Some((start, end, name, args)) = invocation else {
        out.push(text);
        return;
    };
    for definition in definitions_of(context, &name) {
        if !matches!(definition, MacroDefinition::Function { .. }) {
            continue;
        }
        if let Some(inner) = expansion(definition, Some(&args)) {
            let spliced = format!("{} {inner} {}", &text[..start], &text[end..]);
            rescan(context, spliced, depth + 1, out);
        }
    }
}

/// The first invocation in `text` of a name some function-like definition
/// gives: its byte span, the name, and its arguments as written, split at
/// the commas no bracket encloses.
fn nested_invocation(
    context: &ProjectContext,
    text: &str,
) -> Option<(usize, usize, String, Vec<String>)> {
    let tokens = lex_replacement_list(text, false);
    for (i, token) in tokens.iter().enumerate() {
        if token.kind != PpKind::Identifier
            || !tokens.get(i + 1).is_some_and(|t| t.is("("))
            || !definitions_of(context, &token.text)
                .any(|d| matches!(d, MacroDefinition::Function { .. }))
        {
            continue;
        }
        let mut args = vec![Vec::new()];
        let mut depth = 0usize;
        for t in &tokens[i + 2..] {
            if t.is("(") || t.is("[") || t.is("{") {
                depth += 1;
            } else if t.is(")") || t.is("]") || t.is("}") {
                if depth == 0 {
                    let args = args.into_iter().map(|a: Vec<&str>| a.join(" ")).collect();
                    return Some((token.start, t.end, token.text.to_string(), args));
                }
                depth -= 1;
            } else if t.is(",") && depth == 0 {
                args.push(Vec::new());
                continue;
            }
            if let Some(arg) = args.last_mut() {
                arg.push(&t.text);
            }
        }
        return None;
    }
    None
}

/// The replacement `definition` gives an invocation with `args` (none for an
/// object-like macro), its parameters replaced token by token and each
/// `A ## B` joined into one token (C11 6.10.3.3; only a pasting definition,
/// [`ProjectContext::pasting_macro_definitions`], has one). `None` for a
/// definition that cannot be read, or an argument count that does not match.
fn expansion(definition: &MacroDefinition, args: Option<&[String]>) -> Option<String> {
    match definition {
        MacroDefinition::Object { body } if !body.contains("##") => Some(body.clone()),
        MacroDefinition::Object { body } => Some(joined(
            lex_replacement_list(body, false)
                .iter()
                .map(|t| (t.text.to_string(), t.is("##")))
                .collect(),
        )),
        MacroDefinition::Function { params, body } => {
            let args =
                args.filter(|a| a.len() == params.len() || (params.is_empty() && a.len() <= 1))?;
            let tokens = lex_replacement_list(body, true);
            Some(joined(
                tokens
                    .iter()
                    .map(|t| {
                        let replaced = (t.kind == PpKind::Identifier)
                            .then(|| params.iter().position(|p| *p == t.text))
                            .flatten()
                            .and_then(|i| args.get(i));
                        match replaced {
                            Some(arg) => (arg.clone(), false),
                            None => (t.text.to_string(), t.is("##")),
                        }
                    })
                    .collect(),
            ))
        }
        MacroDefinition::Opaque => None,
    }
}

/// `pieces` spaced apart, each one marked as a `##` joining the piece
/// before it to the piece after it (an argument's last token to the next
/// one's first, as the pieces are written).
fn joined(pieces: Vec<(String, bool)>) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut paste_next = false;
    for (piece, is_paste) in pieces {
        if is_paste {
            paste_next = !out.is_empty();
            continue;
        }
        match out.last_mut() {
            Some(last) if paste_next => last.push_str(&piece),
            _ => out.push(piece),
        }
        paste_next = false;
    }
    out.join(" ")
}

/// The names the typedefs `text` stands for declare, when it parses as
/// declarations and nothing else. The invocation's own `;` follows it in
/// the file, outside the expansion (`DECLARE_HANDLE(HWND);` with
/// `typedef HANDLE name` as the body), so a replacement without one is
/// read with it. A tag declared first (`struct name##__ { int unused; };`,
/// DECLARE_HANDLE's STRICT form) is part of such a text.
fn typedef_names_in(text: &str) -> Vec<String> {
    let trimmed = text.trim_end();
    if !trimmed
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|t| t == "typedef")
    {
        return Vec::new();
    }
    let text = if trimmed.ends_with(';') {
        trimmed.to_string()
    } else {
        format!("{trimmed};")
    };
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&crate::parser::c_language()).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(&text, None) else {
        return Vec::new();
    };
    let root = tree.root_node();
    let items: Vec<Node> = root.named_children(&mut root.walk()).collect();
    if root.has_error()
        || items.is_empty()
        || items.iter().any(|d| {
            !matches!(
                d.kind(),
                "declaration"
                    | "type_definition"
                    | "struct_specifier"
                    | "union_specifier"
                    | "enum_specifier"
            )
        })
    {
        return Vec::new();
    }
    crate::utility::cert_c::declarator_utils::typedef_names_declared(&root, &text)
        .into_iter()
        .collect()
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
