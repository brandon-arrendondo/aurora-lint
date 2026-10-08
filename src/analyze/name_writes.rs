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
//! - a type name (`type_identifier`): a typedef the file or the scan knows,
//!   or an ISO C/POSIX `_t` name; one that is neither may be a macro in type
//!   position (`BUMPDECL z;`), so a possible write;
//! - anything else: unclassifiable, so a possible write.
//!
//! A macro whose replacement pastes tokens (`##`) is unreadable: what it
//! names is decided only when it expands.
//!
//! A name a macro's replacement uses that nothing in the scan defines is not
//! classified again at that depth; only the names the body itself spells are.

use crate::analyze::check_macros::MacroDefinition;
use crate::analyze::context::ProjectContext;
use crate::utility::cert_c::ast_utils::{self, get_node_text};
use crate::utility::cert_c::library_effects;
use crate::utility::cert_c::node_children::NodeChildren;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

/// The names a project's scan knows, for a body in one of its files: shared
/// handles on `ProjectContext`'s tables, cheap to take and to keep.
#[derive(Clone, Default)]
pub(crate) struct ProjectNameTables {
    /// Every `#define` across the scanned files and headers.
    pub(crate) macros: Arc<HashMap<String, Vec<MacroDefinition>>>,
    /// Every function name the scan found declared or defined.
    pub(crate) functions: Arc<HashSet<String>>,
    /// Every file-scope object and enumeration constant the scan found
    /// (`global_object_names`): an enumerator from a header is one, and is
    /// no macro.
    pub(crate) objects: Arc<HashSet<String>>,
    /// The typedef names the scan found, by kind: scalar aliases
    /// (`typedef_types`), struct aliases (`struct_typedef_aliases`), and
    /// pointer and function-pointer typedefs.
    pub(crate) scalar_typedefs: Arc<HashMap<String, String>>,
    pub(crate) struct_typedefs: Arc<HashMap<String, String>>,
    pub(crate) pointer_typedefs: Arc<HashSet<String>>,
    pub(crate) function_pointer_typedefs: Arc<HashSet<String>>,
}

impl ProjectNameTables {
    pub(crate) fn of(context: &ProjectContext) -> Self {
        ProjectNameTables {
            macros: Arc::clone(&context.macro_definitions),
            functions: Arc::clone(&context.known_functions),
            objects: Arc::clone(&context.global_object_names),
            scalar_typedefs: Arc::clone(&context.typedef_types),
            struct_typedefs: Arc::clone(&context.struct_typedef_aliases),
            pointer_typedefs: Arc::clone(&context.pointer_typedef_names),
            function_pointer_typedefs: Arc::clone(&context.function_pointer_typedef_names),
        }
    }

    fn names_a_typedef(&self, name: &str) -> bool {
        self.scalar_typedefs.contains_key(name)
            || self.struct_typedefs.contains_key(name)
            || self.pointer_typedefs.contains(name)
            || self.function_pointer_typedefs.contains(name)
    }
}

/// Which writes [`NameScope::may_write`] looks for.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scan {
    /// Every write: an assignment or step of the variable, its address, and
    /// any a name could expand to. With `entered_from_outside`, the stretch
    /// is a loop body that must be entered only from its top, so a label, or
    /// a `case` of a `switch` outside it (Duff's device), counts too.
    Writes { entered_from_outside: bool },
    /// Only what a name could expand to, and the variable's address: for the
    /// rest of a function around a stretch scanned with `Writes`, where a
    /// macro can stash `&v` for the stretch to write through (`SAVE()`
    /// before a loop, `POKE()` inside it) though a plain assignment there
    /// does not matter.
    Expansions,
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
    typedefs: HashSet<String>,
    project: Option<&'a ProjectNameTables>,
}

impl<'a> NameScope<'a> {
    /// The scope of the translation unit `root`, with the project's names
    /// when there are any.
    pub(crate) fn of_file(
        root: &Node,
        source: &str,
        project: Option<&'a ProjectNameTables>,
    ) -> Self {
        let mut scope = NameScope {
            functions: HashSet::new(),
            macros: HashMap::new(),
            enumerators: HashSet::new(),
            typedefs: HashSet::new(),
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
                        // A pasted token is decided at expansion: unreadable.
                        let def = (!body.contains("##")).then_some((params, body));
                        self.macros
                            .entry(get_node_text(&name, source).to_string())
                            .or_default()
                            .push(def);
                    }
                    continue;
                }
                "type_definition" => {
                    let mut declarators = child
                        .children_by_field_name("declarator", &mut child.walk())
                        .collect::<Vec<_>>();
                    for declarator in declarators.drain(..) {
                        if let Some(name) = declared_type_name(&declarator) {
                            self.typedefs
                                .insert(get_node_text(&name, source).to_string());
                        }
                    }
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
    /// `is_var` recognizes, in the sense `scan` gives: its address, a macro
    /// that names it or is handed it, a name this scope cannot classify,
    /// and under [`Scan::Writes`] an assignment or step of it.
    pub(crate) fn may_write(
        &self,
        node: &Node,
        source: &str,
        var: &str,
        is_var: &dyn Fn(&Node) -> bool,
        scan: Scan,
    ) -> bool {
        let mut seen = HashSet::new();
        self.may_write_under(node, node, source, var, is_var, scan, &mut seen)
    }

    #[allow(clippy::too_many_arguments)]
    fn may_write_under(
        &self,
        top: &Node,
        node: &Node,
        source: &str,
        var: &str,
        is_var: &dyn Fn(&Node) -> bool,
        scan: Scan,
        classified: &mut HashSet<String>,
    ) -> bool {
        let writes = matches!(scan, Scan::Writes { .. });
        let entered_from_outside = scan
            == Scan::Writes {
                entered_from_outside: true,
            };
        let target = match node.kind() {
            "labeled_statement" if entered_from_outside => return true,
            "case_statement" if entered_from_outside && !switch_is_inside(node, top) => {
                return true;
            }
            "assignment_expression" if writes => node.child_by_field_name("left"),
            "update_expression" if writes => node.child_by_field_name("argument"),
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
            "type_identifier" => {
                let name = get_node_text(node, source);
                if !classified.contains(name) {
                    let known = if self.is_macro(name) {
                        !self.macro_writes(name, var, &mut HashSet::new())
                    } else {
                        self.names_a_type(name)
                    };
                    if !known {
                        return true;
                    }
                    classified.insert(name.to_string());
                }
                None
            }
            _ => None,
        };
        if target.is_some_and(|t| is_var(&strip_parens(t))) {
            return true;
        }
        node.child_nodes()
            .any(|child| self.may_write_under(top, &child, source, var, is_var, scan, classified))
    }

    /// Whether `name`, in type position and not a macro, names a type: a
    /// typedef this file or the scan declares, or an ISO C/POSIX `_t` name
    /// (POSIX reserves the suffix for types).
    fn names_a_type(&self, name: &str) -> bool {
        self.typedefs.contains(name)
            || self.project.is_some_and(|p| p.names_a_typedef(name))
            || name.ends_with("_t")
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

/// The name a typedef declarator introduces: `T` in `T`, `*T`, `T[4]` or
/// `(*T)(int)`.
fn declared_type_name<'t>(declarator: &Node<'t>) -> Option<Node<'t>> {
    let mut d = *declarator;
    loop {
        if d.kind() == "type_identifier" {
            return Some(d);
        }
        d = d.child_by_field_name("declarator").or_else(|| {
            (d.kind() == "parenthesized_declarator")
                .then(|| d.named_child(0))
                .flatten()
        })?;
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
