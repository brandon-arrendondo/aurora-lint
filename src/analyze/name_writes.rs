//! Whether a stretch of a function body can write one local or parameter,
//! counting the writes a name it uses could expand to.
//!
//! An assignment, an increment or `&v` is visible in the tree. A macro is
//! not: `BUMP();` or a bare `INC;` can expand to `(i += 300)`, and a macro
//! handed `i` (`STEP(i)`) can assign it. So every name the stretch uses must
//! be classified, and one that cannot be is a possible write (ADR-0001: a
//! value is relied on only when the tool proves it).
//!
//! A name is classified as one of:
//! - a macro (this file's or any scanned file's): it writes the variable when
//!   some definition's replacement names it outside the macro's own
//!   parameters, directly or through another known macro, or when the
//!   variable is among its arguments. A definition this module cannot read
//!   (`MacroDefinition::Opaque`) writes;
//! - a function the translation unit or the scan declares, or an ISO C or
//!   POSIX function (C11 7.1.4: one implemented as a macro still behaves as a
//!   function), which receives the variable by value;
//! - an object or enumerator in scope or anywhere in the scan, or a
//!   standard constant macro;
//! - anything else: unclassifiable, so a possible write.
//!
//! A name a macro's replacement uses that nothing in the scan defines is not
//! classified again at that depth; only the names the body itself spells are.

use crate::analyze::check_macros::MacroDefinition;
use crate::utility::cert_c::ast_utils::{self, get_node_text};
use crate::utility::cert_c::library_effects;
use crate::utility::cert_c::node_children::NodeChildren;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// The names a project's scan knows, for a body in one of its files.
#[derive(Clone, Copy)]
pub(crate) struct ProjectNames<'a> {
    /// Every `#define` across the scanned files and headers.
    pub(crate) macros: &'a HashMap<String, Vec<MacroDefinition>>,
    /// Every function name the scan found declared or defined.
    pub(crate) functions: &'a HashSet<String>,
    /// Every file-scope object and enumeration constant the scan found
    /// (`ProjectContext::global_object_names`): an enumerator from a header
    /// is one, and is no macro.
    pub(crate) objects: &'a HashSet<String>,
}

/// One macro definition: its parameters (none for an object-like macro) and
/// replacement text, or `None` for one that cannot be read.
type MacroBody = Option<(Vec<String>, String)>;

/// The names one translation unit declares, and the project's when a scan
/// supplies them.
pub(crate) struct NameScope<'a> {
    functions: HashSet<String>,
    macros: HashMap<String, Vec<MacroBody>>,
    enumerators: HashSet<String>,
    project: Option<ProjectNames<'a>>,
}

impl<'a> NameScope<'a> {
    /// The scope of the translation unit `root`, with the project's names
    /// when there are any.
    pub(crate) fn of_file(root: &Node, source: &str, project: Option<ProjectNames<'a>>) -> Self {
        let mut scope = NameScope {
            functions: HashSet::new(),
            macros: HashMap::new(),
            enumerators: HashSet::new(),
            project,
        };
        scope.collect(root, source);
        scope
    }

    fn collect(&mut self, node: &Node, source: &str) {
        for child in node.child_nodes() {
            match child.kind() {
                "function_definition" | "declaration" => {
                    for declarator in child.child_nodes() {
                        if let Some(name) = declared_function_name(&declarator, source) {
                            self.functions.insert(name);
                        }
                    }
                }
                "preproc_def" | "preproc_function_def" => {
                    if let Some(name) = child.child_by_field_name("name") {
                        let params = child
                            .child_by_field_name("parameters")
                            .map(|p| {
                                p.named_child_nodes()
                                    .filter(|n| n.kind() == "identifier")
                                    .map(|n| get_node_text(&n, source).to_string())
                                    .collect()
                            })
                            .unwrap_or_default();
                        let body = child
                            .child_by_field_name("value")
                            .map(|v| get_node_text(&v, source))
                            .unwrap_or("")
                            .to_string();
                        self.macros
                            .entry(get_node_text(&name, source).to_string())
                            .or_default()
                            .push(Some((params, body)));
                    }
                    continue;
                }
                "enumerator" => {
                    if let Some(name) = child.child_by_field_name("name") {
                        self.enumerators
                            .insert(get_node_text(&name, source).to_string());
                    }
                }
                _ => {}
            }
            self.collect(&child, source);
        }
    }

    /// Whether `name` is a function a call passes arguments to by value: one
    /// this file or the scan declares, or a standard one, and not a macro.
    pub(crate) fn is_plain_function(&self, name: &str) -> bool {
        !self.is_macro(name)
            && (self.functions.contains(name)
                || self.project.is_some_and(|p| p.functions.contains(name))
                || library_effects::library_call_effect(name).is_some())
    }

    fn is_macro(&self, name: &str) -> bool {
        self.macros.contains_key(name) || self.project.is_some_and(|p| p.macros.contains_key(name))
    }

    /// Every definition of the macro `name` this scope knows.
    fn definitions(&self, name: &str) -> Vec<MacroBody> {
        let mut defs = self.macros.get(name).cloned().unwrap_or_default();
        if let Some(project) = self.project {
            for def in project.macros.get(name).into_iter().flatten() {
                defs.push(match def {
                    MacroDefinition::Function { params, body } => {
                        Some((params.clone(), body.clone()))
                    }
                    MacroDefinition::Object { body } => Some((Vec::new(), body.clone())),
                    MacroDefinition::Opaque => None,
                });
            }
        }
        defs
    }

    /// Whether expanding the macro `name` can write `var`: some definition
    /// is unreadable, or names `var` outside its own parameters, here or in
    /// a macro it uses.
    fn macro_writes(&self, name: &str, var: &str, seen: &mut HashSet<String>) -> bool {
        if !seen.insert(name.to_string()) {
            return false;
        }
        for def in self.definitions(name) {
            let Some((params, body)) = def else {
                return true;
            };
            let writes = tokens(&body)
                .filter(|t| !params.iter().any(|p| p == t))
                .any(|t| t == var || (self.is_macro(t) && self.macro_writes(t, var, seen)));
            if writes {
                return true;
            }
        }
        false
    }

    /// Whether anything under `node` can write `var`, an occurrence of which
    /// `is_var` recognizes: an assignment or increment of it, its address, a
    /// macro that names it or is handed it, or a name this scope cannot
    /// classify. With `entered_from_outside`, `node` is a loop body that must
    /// be entered only from its top, so a label, or a `case` of a `switch`
    /// outside it (Duff's device), also counts.
    pub(crate) fn may_write(
        &self,
        node: &Node,
        source: &str,
        var: &str,
        is_var: &dyn Fn(&Node) -> bool,
        entered_from_outside: bool,
    ) -> bool {
        let mut seen = HashSet::new();
        self.may_write_under(
            node,
            node,
            source,
            var,
            is_var,
            entered_from_outside,
            &mut seen,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn may_write_under(
        &self,
        top: &Node,
        node: &Node,
        source: &str,
        var: &str,
        is_var: &dyn Fn(&Node) -> bool,
        entered_from_outside: bool,
        classified: &mut HashSet<String>,
    ) -> bool {
        let target = match node.kind() {
            "labeled_statement" if entered_from_outside => return true,
            "case_statement" if entered_from_outside && !switch_is_inside(node, top) => {
                return true;
            }
            "assignment_expression" => node.child_by_field_name("left"),
            "update_expression" => node.child_by_field_name("argument"),
            "pointer_expression" if node.child(0).is_some_and(|op| op.kind() == "&") => {
                node.child_by_field_name("argument")
            }
            "call_expression" => {
                let callee = node
                    .child_by_field_name("function")
                    .filter(|f| f.kind() == "identifier")
                    .map(|f| get_node_text(&f, source));
                if callee.is_some_and(|c| self.is_macro(c))
                    && node.child_by_field_name("arguments").is_some_and(|args| {
                        args.named_child_nodes().any(|a| contains_var(&a, is_var))
                    })
                {
                    return true;
                }
                None
            }
            "identifier" if !is_var(node) => {
                let name = get_node_text(node, source);
                if !classified.contains(name) {
                    if self.is_macro(name) {
                        if self.macro_writes(name, var, &mut HashSet::new()) {
                            return true;
                        }
                    } else if !self.names_no_macro(name)
                        && ast_utils::resolve_identifier_binding(node, name, source).is_none()
                    {
                        return true;
                    }
                    // Only a verdict that holds wherever the name appears is
                    // kept: a macro is one everywhere, and so is a function,
                    // an enumerator or a standard name. A binding is per
                    // occurrence.
                    if self.is_macro(name) || self.names_no_macro(name) {
                        classified.insert(name.to_string());
                    }
                }
                None
            }
            _ => None,
        };
        if target.is_some_and(|t| is_var(&strip_parens(t))) {
            return true;
        }
        node.child_nodes().any(|child| {
            self.may_write_under(
                top,
                &child,
                source,
                var,
                is_var,
                entered_from_outside,
                classified,
            )
        })
    }

    /// Whether `name`, not a macro, is a function or a constant wherever it
    /// appears: nothing it names can expand to a write.
    fn names_no_macro(&self, name: &str) -> bool {
        self.is_plain_function(name)
            || self.enumerators.contains(name)
            || self.project.is_some_and(|p| p.objects.contains(name))
            || library_effects::standard_object_name(name).is_some()
    }
}

/// Whether the `switch` a `case` label belongs to lies under `top`, so the
/// label can only be reached from inside it.
fn switch_is_inside(case: &Node, top: &Node) -> bool {
    let mut current = case.parent();
    while let Some(node) = current {
        if node.id() == top.id() {
            return false;
        }
        if node.kind() == "switch_statement" {
            return node.start_byte() >= top.start_byte() && node.end_byte() <= top.end_byte();
        }
        current = node.parent();
    }
    false
}

fn contains_var(node: &Node, is_var: &dyn Fn(&Node) -> bool) -> bool {
    is_var(node) || node.child_nodes().any(|c| contains_var(&c, is_var))
}

/// The identifier-like tokens of a replacement list.
fn tokens(body: &str) -> impl Iterator<Item = &str> {
    body.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|t| {
            t.chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        })
}

/// The function a declarator declares: `f` in `f(int)` or `*f(int)`, and
/// nothing for an object, a function pointer included (`(*fp)(int)`).
pub(crate) fn declared_function_name(declarator: &Node, source: &str) -> Option<String> {
    let mut d = *declarator;
    loop {
        match d.kind() {
            "function_declarator" => {
                let name = d.child_by_field_name("declarator")?;
                return (name.kind() == "identifier")
                    .then(|| get_node_text(&name, source).to_string());
            }
            "pointer_declarator" | "attributed_declarator" => {
                d = d.child_by_field_name("declarator")?;
            }
            _ => return None,
        }
    }
}

pub(crate) fn strip_parens(mut node: Node) -> Node {
    while node.kind() == "parenthesized_expression" {
        match node.named_child(0) {
            Some(inner) => node = inner,
            None => break,
        }
    }
    node
}
