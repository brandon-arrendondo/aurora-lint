// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! SIG31-C: Do not access shared objects in signal handlers
//!
//! Accessing shared objects (global/static variables) in signal handlers causes
//! race conditions and undefined behavior. Only `volatile sig_atomic_t` variables
//! may be safely accessed.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! int global_counter = 0;  // Shared, not sig_atomic_t
//! void handler(int sig) {
//!     global_counter++;    // VIOLATION: accessing shared int
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! volatile sig_atomic_t flag = 0;
//! void handler(int sig) {
//!     flag = 1;  // OK: volatile sig_atomic_t
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::{
    declares_static, get_node_text, static_macro_names_in_scope,
};
use crate::utility::cert_c::node_children::NodeChildren;
use crate::utility::cert_c::signal_handlers::RegisteredHandlers;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

/// The atomic type names `<stdatomic.h>` defines (C11 7.17.6, C23 7.17.6).
/// A type is credited as atomic by resolving to one of these names, not by
/// containing `atomic_`: `sig_atomic_t` and a project's own
/// `atomic_counter_t` both contain it.
const STDATOMIC_TYPE_NAMES: &[&str] = &[
    "atomic_flag",
    "atomic_bool",
    "atomic_char",
    "atomic_schar",
    "atomic_uchar",
    "atomic_short",
    "atomic_ushort",
    "atomic_int",
    "atomic_uint",
    "atomic_long",
    "atomic_ulong",
    "atomic_llong",
    "atomic_ullong",
    "atomic_char8_t",
    "atomic_char16_t",
    "atomic_char32_t",
    "atomic_wchar_t",
    "atomic_int_least8_t",
    "atomic_uint_least8_t",
    "atomic_int_least16_t",
    "atomic_uint_least16_t",
    "atomic_int_least32_t",
    "atomic_uint_least32_t",
    "atomic_int_least64_t",
    "atomic_uint_least64_t",
    "atomic_int_fast8_t",
    "atomic_uint_fast8_t",
    "atomic_int_fast16_t",
    "atomic_uint_fast16_t",
    "atomic_int_fast32_t",
    "atomic_uint_fast32_t",
    "atomic_int_fast64_t",
    "atomic_uint_fast64_t",
    "atomic_intptr_t",
    "atomic_uintptr_t",
    "atomic_size_t",
    "atomic_ptrdiff_t",
    "atomic_intmax_t",
    "atomic_uintmax_t",
];

/// Whether a signal handler may touch a file-scope object (C11 7.14.1.1p5):
/// a `volatile sig_atomic_t` or an atomic object may be; anything else may
/// not. Whether an atomic type is lock-free is implementation-defined and
/// not in the source (the rule's compliant solution checks
/// `ATOMIC_INT_LOCK_FREE` and `atomic_is_lock_free`), so every atomic type is
/// credited. `Unknown` is a `sig_atomic_t` reached through a typedef defined
/// in another file, whose qualifiers the project's typedef table does not
/// keep: it is not reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Safety {
    Safe,
    Unsafe,
    Unknown,
}

/// A struct or union type a file-scope object or member has, when this
/// file holds its definition: its member list, and whether the object is
/// `volatile`, which every member reached through it carries
/// (C11 6.5.2.3p3).
#[derive(Clone, Copy)]
struct Record<'a> {
    body: Node<'a>,
    volatile: bool,
}

/// A file-scope object, or a member reached through one: its own safety,
/// and its record type when it is a struct or union this file defines
/// (`st.f` may be a `volatile sig_atomic_t` member of an otherwise
/// unsafe `st`).
#[derive(Clone, Copy)]
struct SharedObject<'a> {
    safety: Safety,
    record: Option<Record<'a>>,
}

/// This file's own type definitions at file scope: typedefs that alias a
/// plain type, and struct and union definitions by tag.
struct FileTypes<'a> {
    typedefs: HashMap<String, Node<'a>>,
    records: HashMap<String, Node<'a>>,
}

/// What a file-scope declarator binds once its array levels are stripped:
/// an object of the declaration's own specifier type, a pointer (with
/// whether that pointer is itself `_Atomic`), or a function.
enum Binding {
    Specified,
    Pointer { atomic: bool },
    Function,
}

pub struct Sig31C {
    /// `typedef name -> aliased type text` as this file sees it, to follow a
    /// typedef defined in a header to `sig_atomic_t` or an atomic type.
    typedefs: RefCell<Arc<HashMap<String, String>>>,
    /// The prescan's context: handlers declared only in a header, and
    /// handlers another file registers (see
    /// `ProjectContext::signal_handlers_registered_elsewhere`).
    project: RefCell<Option<ProjectContext>>,
}

impl Sig31C {
    pub fn new() -> Self {
        Self {
            typedefs: RefCell::default(),
            project: RefCell::new(None),
        }
    }
}

impl CertRule for Sig31C {
    fn rule_id(&self) -> &'static str {
        "SIG31-C"
    }

    fn description(&self) -> &'static str {
        "Do not access shared objects in signal handlers"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "SIG31-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Find all signal handler functions
        let handler_names = self.find_signal_handlers(node, source);

        // Find all global/static variables and their types
        let types = FileTypes::collect(node, source);
        let global_vars = self.find_global_variables(node, source, &types);

        // Check each handler for shared object access
        let access = Access {
            source,
            types: &types,
            global_vars: &global_vars,
        };
        self.check_node(node, &access, &handler_names, &mut violations);

        violations
    }

    fn set_visible_types(&self, types: &crate::analyze::context::VisibleTypes) {
        *self.typedefs.borrow_mut() = Arc::clone(&types.typedef_types);
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.clone());
    }
}

/// What a handler body's accesses are judged against.
struct Access<'s, 'a> {
    source: &'s str,
    types: &'s FileTypes<'a>,
    global_vars: &'s HashMap<String, SharedObject<'a>>,
}

impl<'a> FileTypes<'a> {
    fn collect(root: &Node<'a>, source: &str) -> Self {
        let mut typedefs = HashMap::new();
        Self::collect_typedefs(root, source, &mut typedefs);
        let mut records = HashMap::new();
        Self::collect_records(root, source, &mut records);
        Self { typedefs, records }
    }

    /// Recursively collect this file's typedefs that alias a plain type (no
    /// pointer, array or function declarator), first definition winning, so
    /// their qualifiers can be read as well as the name they alias.
    fn collect_typedefs(node: &Node<'a>, source: &str, typedefs: &mut HashMap<String, Node<'a>>) {
        for child in node.child_nodes() {
            if child.kind() == "type_definition" {
                let mut cursor = child.walk();
                for declarator in child.children_by_field_name("declarator", &mut cursor) {
                    if declarator.kind() == "type_identifier" {
                        typedefs
                            .entry(get_node_text(&declarator, source).to_string())
                            .or_insert(child);
                    }
                }
            } else if child.kind().starts_with("preproc_") {
                Self::collect_typedefs(&child, source, typedefs);
            }
        }
    }

    /// The struct and union definitions whose tag has file scope, first
    /// winning. A tag defined inside a function body is that block's own,
    /// and one defined in a prototype's parameter list ends with that
    /// prototype; neither names a file-scope object's type, so neither is
    /// searched. A definition nested in another struct's member list or in
    /// a declaration's specifiers is still at file scope (C11 6.2.1p4).
    fn collect_records(node: &Node<'a>, source: &str, records: &mut HashMap<String, Node<'a>>) {
        for child in node.child_nodes() {
            match child.kind() {
                "function_definition" | "compound_statement" | "parameter_list" => continue,
                "struct_specifier" | "union_specifier" => {
                    if let (Some(name), Some(body)) = (
                        child.child_by_field_name("name"),
                        child.child_by_field_name("body"),
                    ) {
                        records
                            .entry(get_node_text(&name, source).to_string())
                            .or_insert(body);
                    }
                }
                _ => {}
            }
            Self::collect_records(&child, source, records);
        }
    }

    /// The struct or union type of the objects `decl` (a declaration or
    /// field declaration) declares, when this file defines it: inline, by
    /// tag, or through this file's typedefs, whose `volatile` the objects
    /// carry along with `decl`'s own.
    fn record(&self, decl: &Node<'a>, source: &str) -> Option<Record<'a>> {
        let mut volatile = Sig31C::has_qualifier(decl, source, "volatile");
        let mut ty = decl.child_by_field_name("type")?;
        let mut seen = HashSet::new();
        loop {
            match ty.kind() {
                "struct_specifier" | "union_specifier" => {
                    let body = ty.child_by_field_name("body").or_else(|| {
                        let name = ty.child_by_field_name("name")?;
                        self.records.get(get_node_text(&name, source)).copied()
                    })?;
                    return Some(Record { body, volatile });
                }
                "type_identifier" => {
                    let name = get_node_text(&ty, source);
                    if !seen.insert(name.to_string()) {
                        return None;
                    }
                    let typedef = self.typedefs.get(name)?;
                    volatile |= Sig31C::has_qualifier(typedef, source, "volatile");
                    ty = typedef.child_by_field_name("type")?;
                }
                _ => return None,
            }
        }
    }
}

impl Sig31C {
    /// Recursively collect file-scope declarations, including inside preprocessor blocks.
    fn collect_file_scope_declarations<'a>(node: &Node<'a>, decls: &mut Vec<Node<'a>>) {
        for child in node.child_nodes() {
            if child.kind() == "declaration" {
                decls.push(child);
            } else if child.kind().starts_with("preproc_") {
                Self::collect_file_scope_declarations(&child, decls);
            }
        }
    }

    /// Every function this translation unit registers as a signal handler,
    /// including `sa_sigaction` and `{ .sa_handler = f }` registrations,
    /// resolved by declaration (see [`RegisteredHandlers`]).
    fn find_signal_handlers(&self, node: &Node, source: &str) -> HashSet<String> {
        RegisteredHandlers::collect_in(node, source, self.project.borrow().as_ref())
            .signal_handler_names()
    }

    /// Whether `func`, a definition named `name`, runs as a signal handler:
    /// this file registers it, or another file registers a function of that
    /// name and this definition is not `static` (a `static` one is not the
    /// function the other file names).
    fn is_handler(
        &self,
        func: &Node,
        name: &str,
        source: &str,
        handlers: &HashSet<String>,
    ) -> bool {
        if handlers.contains(name) {
            return true;
        }
        let project = self.project.borrow();
        let Some(project) = project.as_ref() else {
            return false;
        };
        project.signal_handlers_registered_elsewhere.contains(name)
            && !declares_static(
                func,
                source,
                &static_macro_names_in_scope(source, &project.static_macro_names),
            )
    }

    /// Whether `node` (a `declaration`, `field_declaration` or
    /// `type_definition`) carries the type qualifier `qualifier` among its
    /// own specifiers.
    fn has_qualifier(node: &Node, source: &str, qualifier: &str) -> bool {
        node.child_nodes()
            .any(|c| c.kind() == "type_qualifier" && get_node_text(&c, source).trim() == qualifier)
    }

    /// The safety of an object whose type is `decl`'s specifiers: its
    /// qualifiers (with `volatile` also carried from an enclosing object,
    /// for a member), and its type name followed through this file's
    /// typedefs (whose qualifiers count) and then the project's (whose
    /// qualifiers are not recorded).
    fn specifier_safety(
        &self,
        decl: &Node,
        source: &str,
        types: &FileTypes,
        carried_volatile: bool,
    ) -> Safety {
        let mut volatile = carried_volatile || Self::has_qualifier(decl, source, "volatile");
        let mut atomic = Self::has_qualifier(decl, source, "_Atomic");
        let mut qualifiers_known = true;
        let project_typedefs = self.typedefs.borrow();
        let mut name = match decl.child_by_field_name("type") {
            Some(t) if t.kind() == "type_identifier" => get_node_text(&t, source).to_string(),
            _ => String::new(),
        };
        let mut seen = HashSet::new();
        while !name.is_empty() && seen.insert(name.clone()) {
            if name == "sig_atomic_t" {
                return if volatile || atomic {
                    Safety::Safe
                } else if qualifiers_known {
                    Safety::Unsafe
                } else {
                    Safety::Unknown
                };
            }
            if STDATOMIC_TYPE_NAMES.contains(&name.as_str()) {
                return Safety::Safe;
            }
            if let Some(typedef) = types.typedefs.get(&name) {
                volatile |= Self::has_qualifier(typedef, source, "volatile");
                atomic |= Self::has_qualifier(typedef, source, "_Atomic");
                name = match typedef.child_by_field_name("type") {
                    Some(t) if t.kind() == "type_identifier" => {
                        get_node_text(&t, source).to_string()
                    }
                    _ => String::new(),
                };
            } else if let Some(next) = project_typedefs.get(&name) {
                qualifiers_known = false;
                name = next.trim().to_string();
            } else {
                break;
            }
        }
        if atomic {
            Safety::Safe
        } else {
            Safety::Unsafe
        }
    }

    /// The safety of what `binding` binds, given its specifiers' safety;
    /// `None` for a function, which is not a shared object.
    fn binding_safety(binding: &Binding, specified: Safety) -> Option<Safety> {
        match binding {
            Binding::Specified => Some(specified),
            Binding::Pointer { atomic: true } => Some(Safety::Safe),
            Binding::Pointer { atomic: false } => Some(Safety::Unsafe),
            Binding::Function => None,
        }
    }

    /// The object `decl` declares through `declarator`, with the safety and
    /// record type of what it binds (`carried_volatile` from an enclosing
    /// object, for a member); `None` for a function or an unreadable
    /// declarator.
    fn declared_object<'a>(
        &self,
        decl: &Node<'a>,
        declarator: Node<'a>,
        source: &str,
        types: &FileTypes<'a>,
        carried_volatile: bool,
    ) -> Option<(String, SharedObject<'a>)> {
        let (name, binding) = Self::declarator_binding(declarator, source)?;
        let specified = self.specifier_safety(decl, source, types, carried_volatile);
        let safety = Self::binding_safety(&binding, specified)?;
        // Only an object of the record type itself, or an element of an
        // array of it, has its members reached by `.member`.
        let record = match binding {
            Binding::Specified => types.record(decl, source).map(|r| Record {
                volatile: r.volatile || carried_volatile,
                ..r
            }),
            _ => None,
        };
        Some((name, SharedObject { safety, record }))
    }

    /// The member `name` of `record`, looked up through anonymous struct and
    /// union members too, carrying the object's `volatile`.
    fn member<'a>(
        &self,
        record: Record<'a>,
        name: &str,
        source: &str,
        types: &FileTypes<'a>,
    ) -> Option<SharedObject<'a>> {
        for field in record.body.child_nodes() {
            if field.kind() != "field_declaration" {
                continue;
            }
            let mut cursor = field.walk();
            let declarators: Vec<Node> = field
                .children_by_field_name("declarator", &mut cursor)
                .collect();
            if declarators.is_empty() {
                // An anonymous struct or union: its members are members of
                // the enclosing one (C11 6.7.2.1p13).
                let anonymous = field
                    .child_by_field_name("type")
                    .filter(|t| t.child_by_field_name("name").is_none())
                    .and_then(|t| t.child_by_field_name("body"));
                if let Some(body) = anonymous {
                    let inner = Record {
                        body,
                        volatile: record.volatile
                            || Self::has_qualifier(&field, source, "volatile"),
                    };
                    if let Some(found) = self.member(inner, name, source, types) {
                        return Some(found);
                    }
                }
                continue;
            }
            for declarator in declarators {
                if let Some((member, object)) =
                    self.declared_object(&field, declarator, source, types, record.volatile)
                {
                    if member == name {
                        return Some(object);
                    }
                }
            }
        }
        None
    }

    fn find_global_variables<'a>(
        &self,
        node: &Node<'a>,
        source: &str,
        types: &FileTypes<'a>,
    ) -> HashMap<String, SharedObject<'a>> {
        let mut vars = HashMap::new();

        // Look at file-scope declarations, including those inside preprocessor blocks
        if node.kind() == "translation_unit" {
            let mut decls = Vec::new();
            Self::collect_file_scope_declarations(node, &mut decls);
            for decl in &decls {
                let mut cursor = decl.walk();
                for declarator in decl.children_by_field_name("declarator", &mut cursor) {
                    if let Some((name, object)) =
                        self.declared_object(decl, declarator, source, types, false)
                    {
                        vars.insert(name, object);
                    }
                }
            }
        }

        vars
    }

    /// The name `declarator` declares and what it binds, read from the
    /// declarator nearest the name outward: array levels give elements of the
    /// next level's type, and the first pointer or function level decides.
    /// `int *a[3]` binds pointers, `int (*a)[3]` a pointer, `int *f(void)` a
    /// function, and `T *_Atomic p` an atomic pointer.
    fn declarator_binding(declarator: Node, source: &str) -> Option<(String, Binding)> {
        let mut levels = Vec::new();
        let mut node = declarator;
        loop {
            match node.kind() {
                "identifier" | "field_identifier" => break,
                "init_declarator" => node = node.child_by_field_name("declarator")?,
                "parenthesized_declarator" | "attributed_declarator" => {
                    node = node.named_child_nodes().next()?
                }
                "pointer_declarator" | "array_declarator" | "function_declarator" => {
                    levels.push(node);
                    node = node.child_by_field_name("declarator")?;
                }
                _ => return None,
            }
        }
        let name = get_node_text(&node, source).to_string();
        let binding = match levels.iter().rev().find(|l| l.kind() != "array_declarator") {
            None => Binding::Specified,
            Some(level) if level.kind() == "function_declarator" => Binding::Function,
            Some(level) => Binding::Pointer {
                atomic: Self::has_qualifier(level, source, "_Atomic"),
            },
        };
        Some((name, binding))
    }

    /// The safety of what the handler accesses when it names `object` at
    /// `id`: the object itself, or the element or member the enclosing
    /// expression selects from it, walking out through parentheses,
    /// subscripts and `.member` (`a[i].f`, `(st).f`, `st.inner.f`). An
    /// element has the object's own (array-stripped) type; `->` and `*`
    /// read the object itself, a pointer.
    fn accessed_safety<'a>(
        &self,
        id: Node,
        mut object: SharedObject<'a>,
        access: &Access<'_, 'a>,
    ) -> Safety {
        let mut node = id;
        while let Some(parent) = node.parent() {
            let is_operand = |field: &str| {
                parent
                    .child_by_field_name(field)
                    .is_some_and(|c| c.id() == node.id())
            };
            match parent.kind() {
                "parenthesized_expression" => {}
                "subscript_expression" if is_operand("argument") => {}
                "field_expression"
                    if is_operand("argument")
                        && parent
                            .child_by_field_name("operator")
                            .is_some_and(|op| get_node_text(&op, access.source) == ".") =>
                {
                    let member = object
                        .record
                        .zip(parent.child_by_field_name("field"))
                        .and_then(|(record, field)| {
                            self.member(
                                record,
                                get_node_text(&field, access.source),
                                access.source,
                                access.types,
                            )
                        });
                    // A member this file's definition does not show keeps
                    // the object's own safety.
                    match member {
                        Some(member) => object = member,
                        None => break,
                    }
                }
                _ => break,
            }
            node = parent;
        }
        object.safety
    }

    fn check_node(
        &self,
        node: &Node,
        access: &Access,
        handlers: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            if let Some(declarator) = func.child_by_field_name("declarator") {
                if let Some(func_name) = self.get_function_name_text(&declarator, access.source) {
                    if self.is_handler(&func, &func_name, access.source, handlers) {
                        if let Some(body) = func.child_by_field_name("body") {
                            self.check_handler_body(&body, access, &func_name, violations);
                        }
                    }
                }
            }
        }
    }

    fn get_function_name_text(&self, declarator: &Node, source: &str) -> Option<String> {
        if declarator.kind() == "function_declarator" {
            if let Some(inner) = declarator.child_by_field_name("declarator") {
                let text = get_node_text(&inner, source);
                return Some(text.to_string());
            }
        }

        if declarator.kind() == "pointer_declarator" {
            if let Some(inner) = declarator.child_by_field_name("declarator") {
                return self.get_function_name_text(&inner, source);
            }
        }

        if declarator.kind() == "identifier" {
            let text = get_node_text(&declarator, source);
            return Some(text.to_string());
        }

        None
    }

    fn check_handler_body(
        &self,
        body: &Node,
        access: &Access,
        handler_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Collect all local variables declared in this handler
        let mut local_vars = HashSet::new();
        self.collect_local_vars(body, access.source, &mut local_vars);

        self.check_for_global_access(body, access, handler_name, &local_vars, violations);
    }

    fn collect_local_vars(&self, node: &Node, source: &str, locals: &mut HashSet<String>) {
        for decl in query::find_descendants_of_kind(*node, "declaration") {
            if let Some(declarator) = decl.child_by_field_name("declarator") {
                self.extract_local_var_names(&declarator, source, locals);
            }
        }
    }

    fn extract_local_var_names(
        &self,
        declarator: &Node,
        source: &str,
        locals: &mut HashSet<String>,
    ) {
        match declarator.kind() {
            "identifier" => {
                let var_name = get_node_text(&declarator, source);
                locals.insert(var_name.to_string());
            }
            "init_declarator" => {
                if let Some(inner) = declarator.child_by_field_name("declarator") {
                    self.extract_local_var_names(&inner, source, locals);
                }
            }
            "pointer_declarator" | "array_declarator" | "function_declarator" => {
                if let Some(inner) = declarator.child_by_field_name("declarator") {
                    self.extract_local_var_names(&inner, source, locals);
                }
            }
            _ => {
                for child in declarator.child_nodes() {
                    if child.kind() == "identifier" {
                        let var_name = get_node_text(&child, source);
                        locals.insert(var_name.to_string());
                    } else if child.kind() != "," {
                        self.extract_local_var_names(&child, source, locals);
                    }
                }
            }
        }
    }

    /// Report each use of a shared object in the handler whose accessed
    /// object, element or member is not safe. Each use is judged once, at
    /// the identifier naming the object, whatever expression selects from it.
    fn check_for_global_access(
        &self,
        node: &Node,
        access: &Access,
        handler_name: &str,
        local_vars: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kind(*node, "identifier") {
            let id_name = get_node_text(&n, access.source);

            // Skip if it's a local variable
            if local_vars.contains(id_name) {
                continue; // Don't treat this identifier as a global access
            }

            // Skip if this identifier is used as an argument to an async-signal-safe function
            if self.is_used_in_async_safe_call(&n, access.source) {
                continue;
            }

            let Some(&object) = access.global_vars.get(id_name) else {
                continue;
            };
            if self.accessed_safety(n, object, access) == Safety::Unsafe {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Signal handler '{}' accesses shared object '{}' which is not 'volatile sig_atomic_t'",
                        handler_name, id_name
                    ),
                    file_path: String::new(),
                    line: n.start_position().row + 1,
                    column: n.start_position().column + 1,
                    suggestion: Some(
                        "Change variable to 'volatile sig_atomic_t' or use a flag-based approach where the handler only sets a volatile sig_atomic_t flag".to_string()
                    ),
                    ..Default::default()
                });
            }
        }
    }

    /// Check if this identifier is used as an argument to an async-signal-safe function
    /// Common async-signal-safe functions: write, read, _exit, signal, raise, abort, etc.
    fn is_used_in_async_safe_call(&self, node: &Node, source: &str) -> bool {
        // Walk up the AST to find if we're inside a call_expression
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "call_expression" {
                if let Some(function) = parent.child_by_field_name("function") {
                    let func_name = get_node_text(&function, source);

                    // List of async-signal-safe functions from POSIX
                    // https://man7.org/linux/man-pages/man7/signal-safety.7.html
                    let async_safe_funcs = [
                        "write",
                        "read",
                        "_exit",
                        "_Exit",
                        "abort",
                        "raise",
                        "signal",
                        "sigaction",
                        "sigaddset",
                        "sigdelset",
                        "sigemptyset",
                        "sigfillset",
                        "sigismember",
                        "sigpending",
                        "sigprocmask",
                        "sigsuspend",
                        "kill",
                        "pause",
                        "sleep",
                        "alarm",
                        "getpid",
                        "getppid",
                        "getuid",
                        "geteuid",
                        "getgid",
                        "getegid",
                        "close",
                        "dup",
                        "dup2",
                        "fcntl",
                        "pipe",
                    ];

                    if async_safe_funcs.contains(&func_name) {
                        return true;
                    }
                }
                // Don't continue searching up past the call_expression
                return false;
            }

            // Don't search past function boundaries
            if parent.kind() == "function_definition" {
                return false;
            }

            current = parent.parent();
        }

        false
    }
}
