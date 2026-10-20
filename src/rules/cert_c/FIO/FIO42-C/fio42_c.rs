// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! FIO42-C: Close files when they are no longer needed
//!
//! A call to fopen() or freopen() must be matched with a call to fclose()
//! before the lifetime of the last pointer that stores the return value ends
//! or before normal program termination.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! void process_file(const char *filename) {
//!     FILE *fp = fopen(filename, "r");
//!     if (fp == NULL) {
//!         return;
//!     }
//!     // ... process file ...
//!     return; // FILE* leak - fclose() never called
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! void process_file(const char *filename) {
//!     FILE *fp = fopen(filename, "r");
//!     if (fp == NULL) {
//!         return;
//!     }
//!     // ... process file ...
//!     if (fclose(fp) != 0) {
//!         // Handle error
//!     }
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::analyze::context::ScopedTable;
use crate::analyze::context::SummaryLookup;
use crate::analyze::function_summary::FunctionSummary;
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::{
    declaration_has_storage_class, get_node_text, ScopeDeclarations,
};
use crate::utility::cert_c::guard_dominance::dominating_conditions_with_branches;
use crate::utility::cert_c::std_functions::is_known_standard_function;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

#[derive(Default)]
pub struct Fio42C {
    function_summaries: RefCell<ScopedTable<FunctionSummary>>,
}

impl Fio42C {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CertRule for Fio42C {
    fn reads_header_facts(&self) -> bool {
        true
    }

    fn rule_id(&self) -> &'static str {
        "FIO42-C"
    }

    fn description(&self) -> &'static str {
        "Close files when they are no longer needed"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "FIO42-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let summaries = self.function_summaries.borrow();

        // Track file resources across the AST
        let mut tracker = FileResourceTracker::new(*node);
        tracker.analyze_node(node, source, &summaries, &mut violations);

        violations
    }
}

/// The object a handle is held in: the declaration that binds the name and
/// the name it binds there (one declaration can declare several).
type ObjectKey = (usize, String);

struct FileResourceTracker<'t> {
    root: Node<'t>,
    declarations: ScopeDeclarations<'t>,
    // Opened handles in the current function, one per object, in the order
    // first opened; a later open into the same object takes its position.
    resources: Vec<(ObjectKey, ResourceInfo)>,
    // Objects whose handle was closed or left this function's ownership.
    released: HashSet<ObjectKey>,
    // Plain copies between locals (`FILE *out = f;`): a close or escape of
    // either name is one of the handle.
    aliases: HashMap<ObjectKey, ObjectKey>,
    // Local pointers that only ever hold a local's address, to that local.
    pointers: HashMap<ObjectKey, ObjectKey>,
}

#[derive(Clone)]
#[allow(dead_code)]
struct ResourceInfo {
    var_name: String,
    resource_type: ResourceType,
    line: usize,
    column: usize,
}

#[derive(Clone, PartialEq)]
#[allow(clippy::enum_variant_names)]
enum ResourceType {
    FilePointer,    // FILE* from fopen/freopen
    FileDescriptor, // int fd from open()
    FileHandle,     // HANDLE from CreateFile()
}

impl<'t> FileResourceTracker<'t> {
    fn new(root: Node<'t>) -> Self {
        Self {
            root,
            declarations: ScopeDeclarations::indexed(root),
            resources: Vec::new(),
            released: HashSet::new(),
            aliases: HashMap::new(),
            pointers: HashMap::new(),
        }
    }

    fn analyze_node(
        &mut self,
        node: &Node<'t>,
        source: &str,
        summaries: &(impl SummaryLookup + ?Sized),
        violations: &mut Vec<RuleViolation>,
    ) {
        // Find all function definitions to analyze
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            self.analyze_function(&func, source, summaries, violations);
        }
    }

    fn analyze_function(
        &mut self,
        func_node: &Node<'t>,
        source: &str,
        summaries: &(impl SummaryLookup + ?Sized),
        violations: &mut Vec<RuleViolation>,
    ) {
        // Reset tracking for this function scope
        self.resources.clear();
        self.released.clear();
        self.aliases.clear();
        self.pointers.clear();

        // Get function body
        if let Some(body) = func_node.child_by_field_name("body") {
            // Collect all resource allocations
            self.collect_resources(func_node, &body, source);

            // Collect closes, and the uses that hand the handle to something
            // that outlives this function: once a handle is returned, stored
            // through a pointer, a field or a file-scope variable, or given to
            // a callee that keeps it, closing it is no longer this function's
            // job.
            //
            // Interprocedural: a resource passed by value to a sink function
            // that closes the corresponding parameter (directly, or
            // transitively through a chain of forwarding helpers) is closed
            // as far as this function's scope is concerned, even though the
            // `fclose`/`close`/`CloseHandle` call itself lives in the
            // callee's body (e.g. Juliet CWE-773 variants 21/22/
            // 41/42/45/51-54/63-66, where a goodB2GSink helper closes the
            // FILE* it's handed).
            if !self.resources.is_empty() {
                self.collect_releases(func_node, &body, source, summaries);
            }

            // Check for unclosed resources
            self.check_unclosed_resources(violations);

            // CWE-459: check for temp file creation without cleanup
            self.check_temp_file_cleanup(&body, source, violations);
        }
    }

    /// The local object `ident` names in `func`: its declaration lies inside
    /// the function (a parameter or a block-scope variable) and has automatic
    /// storage. A file-scope variable, a `static` or `extern` one, or a name
    /// the scan cannot resolve outlives the call, so a handle in it is not
    /// this function's to close.
    fn local_object(&self, func: &Node, ident: &Node<'t>, source: &str) -> Option<ObjectKey> {
        let name = get_node_text(ident, source);
        let (declaration, _) = self
            .declarations
            .resolve_identifier_declarator_in(&self.root, ident, name, source)?;
        let inside = declaration.start_byte() >= func.start_byte()
            && declaration.end_byte() <= func.end_byte();
        let lasting = declaration.kind() == "declaration"
            && (declaration_has_storage_class(&declaration, "static", source)
                || declaration_has_storage_class(&declaration, "extern", source));
        (inside && !lasting).then(|| (declaration.id(), name.to_string()))
    }

    fn collect_resources(&mut self, func: &Node, body: &Node<'t>, source: &str) {
        for n in
            query::find_descendants_of_kinds(*body, &["init_declarator", "assignment_expression"])
        {
            // Classify by the actual function called. Substring matching is
            // unsound here because `fopen(`/`freopen(` both contain `open(`,
            // which would otherwise track a FILE* as both a FILE pointer and
            // a POSIX file descriptor.
            let (target, value) = match n.kind() {
                "init_declarator" => (
                    n.child_by_field_name("declarator")
                        .and_then(|d| declared_identifier(&d)),
                    n.child_by_field_name("value"),
                ),
                _ if is_plain_assignment(&n) => (
                    n.child_by_field_name("left").map(|l| unwrap_held(&l)),
                    n.child_by_field_name("right"),
                ),
                _ => continue,
            };
            let (Some(target), Some(value)) = (target, value) else {
                continue;
            };
            let Some(rtype) = Self::callee_name(&value, source)
                .as_deref()
                .and_then(Self::classify_callee)
            else {
                continue;
            };
            // `c->f = fopen(...)`, `*out = open(...)` and `g_log = fopen(...)`
            // store the handle somewhere the caller still reaches.
            if target.kind() != "identifier" {
                continue;
            }
            let Some(key) = self.local_object(func, &target, source) else {
                continue;
            };
            let at = if n.kind() == "init_declarator" {
                n.parent().unwrap_or(n)
            } else {
                n
            };
            self.track_resource(key, rtype, &at);
        }
    }

    /// Record an opened resource of the given kind, keyed on the object that
    /// holds it, positioned at `node`.
    fn track_resource(&mut self, key: ObjectKey, rtype: ResourceType, node: &Node) {
        let info = ResourceInfo {
            var_name: key.1.clone(),
            resource_type: rtype,
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
        };
        match self.resources.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = info,
            None => self.resources.push((key, info)),
        }
    }

    /// The tracked objects whose handle `expr` evaluates to: through
    /// parentheses, casts and either arm of a `?:`.
    fn held_objects(&self, func: &Node, expr: &Node<'t>, source: &str) -> Vec<ObjectKey> {
        let mut held = Vec::new();
        let mut stack = vec![*expr];
        while let Some(e) = stack.pop() {
            match e.kind() {
                "parenthesized_expression" => stack.extend(e.named_child(0)),
                "cast_expression" => stack.extend(e.child_by_field_name("value")),
                "conditional_expression" => {
                    stack.extend(e.child_by_field_name("consequence"));
                    stack.extend(e.child_by_field_name("alternative"));
                }
                "identifier" => {
                    if let Some(key) = self.local_object(func, &e, source) {
                        // The pointer reaches the local it points to.
                        if let Some(pointee) = self.pointers.get(&key) {
                            if self.is_tracked(pointee) {
                                held.push(pointee.clone());
                            }
                        }
                        if self.is_tracked(&key) {
                            held.push(key);
                        }
                    }
                }
                "field_expression" => {
                    if let Some(key) = self.member_owner(func, &e, source) {
                        if self.is_tracked(&key) {
                            held.push(key);
                        }
                    }
                }
                "pointer_expression" => {
                    if let Some(key) = self.pointee(func, &e, source) {
                        if self.is_tracked(&key) {
                            held.push(key);
                        }
                    }
                }
                _ => {}
            }
        }
        held
    }

    fn is_tracked(&self, key: &ObjectKey) -> bool {
        let root = self.alias_root(key);
        self.resources
            .iter()
            .any(|(k, _)| self.alias_root(k) == root)
    }

    fn alias_root(&self, key: &ObjectKey) -> ObjectKey {
        let mut key = key.clone();
        while let Some(next) = self.aliases.get(&key) {
            key = next.clone();
        }
        key
    }

    /// Whether a handle of kind `kind` was opened into `key`'s object or a
    /// copy of it.
    fn holds_kind(&self, key: &ObjectKey, kind: &ResourceType) -> bool {
        let root = self.alias_root(key);
        self.resources
            .iter()
            .any(|(k, info)| info.resource_type == *kind && self.alias_root(k) == root)
    }

    /// The local an assignment or initializer copies a handle into, or `None`
    /// when the destination outlives the call. A store through a pointer that
    /// only ever holds a local's address lands in that local.
    fn copy_target(&self, func: &Node, target: &Node<'t>, source: &str) -> Option<ObjectKey> {
        match target.kind() {
            "identifier" => self.local_object(func, target, source),
            "field_expression" => self.member_owner(func, target, source),
            _ => self.pointee(func, target, source),
        }
    }

    /// The local aggregate a `.` member access lies inside (`u.first`,
    /// `s.in.fp`): a handle stored there is still this function's, the whole
    /// aggregate standing for it. Through `->` the member is in storage the
    /// local only points to.
    fn member_owner(&self, func: &Node, expr: &Node<'t>, source: &str) -> Option<ObjectKey> {
        let mut e = *expr;
        while e.kind() == "field_expression" {
            let dot = e
                .child_by_field_name("operator")
                .map(|o| get_node_text(&o, source));
            if dot != Some(".") {
                return None;
            }
            e = unwrap_held(&e.child_by_field_name("argument")?);
        }
        (e.kind() == "identifier")
            .then(|| self.local_object(func, &e, source))
            .flatten()
    }

    /// The local `*p` designates when `p` is in [`Self::pointers`].
    fn pointee(&self, func: &Node, expr: &Node<'t>, source: &str) -> Option<ObjectKey> {
        if expr.kind() != "pointer_expression"
            || expr
                .child_by_field_name("operator")
                .is_none_or(|o| get_node_text(&o, source) != "*")
        {
            return None;
        }
        let pointer = unwrap_held(&expr.child_by_field_name("argument")?);
        if pointer.kind() != "identifier" {
            return None;
        }
        let key = self.local_object(func, &pointer, source)?;
        self.pointers.get(&key).cloned()
    }

    /// Local pointers set once, where they are declared, to the address of
    /// another local (`FILE **pp = &f;`) and never assigned again: `*pp` is
    /// that local, and taking its address there hands it to nobody. Returns
    /// the `&local` expressions those declarations hold.
    fn collect_pointers(&mut self, func: &Node, body: &Node<'t>, source: &str) -> HashSet<usize> {
        let mut assigned = HashSet::new();
        for a in
            query::find_descendants_of_kinds(*body, &["assignment_expression", "update_expression"])
        {
            let left = a
                .child_by_field_name("left")
                .or_else(|| a.child_by_field_name("argument"));
            if let Some(left) = left.map(|l| unwrap_held(&l)) {
                if left.kind() == "identifier" {
                    assigned.extend(self.local_object(func, &left, source));
                }
            }
        }
        let mut addresses = HashSet::new();
        for init in query::find_descendants_of_kind(*body, "init_declarator") {
            let Some(pointer) = init
                .child_by_field_name("declarator")
                .and_then(|d| declared_identifier(&d))
            else {
                continue;
            };
            let Some(value) = init.child_by_field_name("value").map(|v| unwrap_held(&v)) else {
                continue;
            };
            let Some(pointee) = address_of_identifier(&value, source) else {
                continue;
            };
            let (Some(pointer_key), Some(pointee_key)) = (
                self.local_object(func, &pointer, source),
                self.local_object(func, &pointee, source),
            ) else {
                continue;
            };
            if assigned.contains(&pointer_key) {
                continue;
            }
            self.pointers.insert(pointer_key, pointee_key);
            addresses.insert(value.id());
        }
        addresses
    }

    fn release(&mut self, key: &ObjectKey) {
        self.released.insert(self.alias_root(key));
    }

    fn alias(&mut self, copy: ObjectKey, of: &ObjectKey) {
        let (copy, of) = (self.alias_root(&copy), self.alias_root(of));
        if copy == of {
            return;
        }
        // A copy that already let go of its handle lets go of this one.
        if self.released.contains(&copy) {
            self.released.insert(of.clone());
        }
        self.aliases.insert(copy, of);
    }

    fn collect_releases(
        &mut self,
        func: &Node<'t>,
        body: &Node<'t>,
        source: &str,
        summaries: &(impl SummaryLookup + ?Sized),
    ) {
        let local_addresses = self.collect_pointers(func, body, source);
        // Copies first, in source order, so a close of the copy credits the
        // original wherever it is written.
        for n in
            query::find_descendants_of_kinds(*body, &["init_declarator", "assignment_expression"])
        {
            let (target, value) = match n.kind() {
                "init_declarator" => (
                    n.child_by_field_name("declarator")
                        .and_then(|d| declared_identifier(&d)),
                    n.child_by_field_name("value"),
                ),
                _ if is_plain_assignment(&n) => (
                    n.child_by_field_name("left").map(|l| unwrap_held(&l)),
                    n.child_by_field_name("right"),
                ),
                _ => continue,
            };
            let Some(value) = value else { continue };
            if value.kind() == "initializer_list" {
                // `struct conn c = { .f = f }` puts the handle in an object
                // this scan does not follow.
                for ident in query::find_descendants_of_kind(value, "identifier") {
                    for key in self.held_objects(func, &ident, source) {
                        self.release(&key);
                    }
                }
                continue;
            }
            let held = self.held_objects(func, &value, source);
            if held.is_empty() {
                continue;
            }
            let copy = target.and_then(|t| self.copy_target(func, &t, source));
            for key in held {
                match &copy {
                    Some(copy) => self.alias(copy.clone(), &key),
                    None => self.release(&key),
                }
            }
        }

        for n in query::find_descendants_of_kinds(
            *body,
            &["call_expression", "return_statement", "pointer_expression"],
        ) {
            match n.kind() {
                "return_statement" => {
                    let Some(value) = n.named_child(0) else {
                        continue;
                    };
                    for key in self.held_objects(func, &value, source) {
                        if !returned_on_failure(&n, &key.1, source) {
                            self.release(&key);
                        }
                    }
                }
                // `&f` lets whatever receives the address close or keep it.
                "pointer_expression" => {
                    if !local_addresses.contains(&n.id())
                        && n.child_by_field_name("operator")
                            .is_some_and(|o| get_node_text(&o, source) == "&")
                    {
                        if let Some(arg) = n.child_by_field_name("argument") {
                            for key in self.held_objects(func, &arg, source) {
                                self.release(&key);
                            }
                        }
                    }
                }
                _ => self.credit_call(func, &n, source, summaries),
            }
        }
    }

    /// A close (`fclose`/`close`/`CloseHandle` on the handle), a call to a
    /// function whose summary closes or keeps the parameter the handle is
    /// passed in, or a call to a function nothing in the scan speaks for.
    fn credit_call(
        &mut self,
        func: &Node<'t>,
        call: &Node<'t>,
        source: &str,
        summaries: &(impl SummaryLookup + ?Sized),
    ) {
        let (Some(function), Some(arguments)) = (
            call.child_by_field_name("function"),
            call.child_by_field_name("arguments"),
        ) else {
            return;
        };
        let callee_name = get_node_text(&function, source).trim();
        // Each close releases only its own kind of handle: `_close((int)fp)`
        // or `CloseHandle((HANDLE)fp)` leaves the stream open (CERT asks for
        // the matching close).
        let closes = match callee_name {
            "fclose" => Some(ResourceType::FilePointer),
            "close" | "_close" => Some(ResourceType::FileDescriptor),
            "CloseHandle" => Some(ResourceType::FileHandle),
            _ => None,
        };
        let closer = closes.is_some();
        // A release credited here stops a leak report, so every definition
        // this call can link with must close or keep the handle.
        let summary = summaries
            .get(callee_name)
            .map(|s| s.at_all(source, call.start_position().row + 1));
        // A callee the scan has no body for, and no library contract speaks
        // for, may close or keep what it is handed: a call through a pointer,
        // a function another translation unit defines, a macro. A library
        // function (`fgetc`, `read`, `fstat`) uses the handle and gives it
        // back.
        let unknown = !closer
            && summary.is_none()
            && (function.kind() != "identifier" || !is_known_standard_function(callee_name));
        let mut cursor = arguments.walk();
        for (idx, arg) in arguments.named_children(&mut cursor).enumerate() {
            let releases = unknown
                || (!closer
                    && summary.as_ref().is_some_and(|s| {
                        s.closes_params.contains(&idx) || s.stores_params.contains(&idx)
                    }));
            for key in self.held_objects(func, &arg, source) {
                let closed = idx == 0 && closes.as_ref().is_some_and(|k| self.holds_kind(&key, k));
                if releases || closed {
                    self.release(&key);
                }
            }
        }
    }

    /// Name of the first function called within an initializer / RHS expression
    /// (e.g. `fopen` from `fopen(...)` or `(FILE *)fopen(...)`).
    fn callee_name(node: &Node, source: &str) -> Option<String> {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                return Some(get_node_text(&function, source).trim().to_string());
            }
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(name) = Self::callee_name(&child, source) {
                    return Some(name);
                }
            }
        }
        None
    }

    /// Map an opener function name to the kind of resource it returns. Returns
    /// `None` for functions this rule does not track.
    fn classify_callee(name: &str) -> Option<ResourceType> {
        match name {
            "fopen" | "freopen" => Some(ResourceType::FilePointer),
            "open" => Some(ResourceType::FileDescriptor),
            "CreateFile" | "CreateFileA" | "CreateFileW" => Some(ResourceType::FileHandle),
            _ => None,
        }
    }

    fn check_unclosed_resources(&self, violations: &mut Vec<RuleViolation>) {
        for (key, info) in &self.resources {
            if self.released.contains(&self.alias_root(key)) {
                continue;
            }
            let var_name = &info.var_name;
            let (message, suggestion) = match info.resource_type {
                ResourceType::FilePointer => (
                    format!(
                        "FILE pointer '{}' opened with fopen/freopen but never closed with fclose()",
                        var_name
                    ),
                    format!(
                        "Add fclose({}) before function returns or program exits",
                        var_name
                    ),
                ),
                ResourceType::FileDescriptor => (
                    format!(
                        "File descriptor '{}' opened with open() but never closed with close()",
                        var_name
                    ),
                    format!(
                        "Add close({}) before function returns or program exits",
                        var_name
                    ),
                ),
                ResourceType::FileHandle => (
                    format!(
                        "File HANDLE '{}' opened with CreateFile() but never closed with CloseHandle()",
                        var_name
                    ),
                    format!(
                        "Add CloseHandle({}) before function returns or program exits",
                        var_name
                    ),
                ),
            };
            violations.push(RuleViolation {
                rule_id: "FIO42-C".to_string(),
                message,
                severity: Severity::High,
                line: info.line,
                column: info.column,
                file_path: String::new(),
                suggestion: Some(suggestion),
                requires_manual_review: None,
            });
        }
    }

    // ── CWE-459: Temp file creation without cleanup ─────────────────────────

    /// Check if a function creates temp files but never deletes them
    fn check_temp_file_cleanup(
        &self,
        body: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let mut temp_creations: Vec<(usize, usize)> = Vec::new();
        let mut has_cleanup = false;
        self.scan_temp_file_calls(body, source, &mut temp_creations, &mut has_cleanup);

        if !has_cleanup {
            for (line, col) in &temp_creations {
                violations.push(RuleViolation {
                    rule_id: "FIO42-C".to_string(),
                    message:
                        "Temporary file created but never deleted (missing unlink/remove call)"
                            .to_string(),
                    severity: Severity::Medium,
                    line: *line,
                    column: *col,
                    file_path: String::new(),
                    suggestion: Some(
                        "Call unlink() or remove() on the temporary file before function returns"
                            .to_string(),
                    ),
                    requires_manual_review: None,
                });
            }
        }
    }

    /// Recursively scan for temp file creation and cleanup calls
    fn scan_temp_file_calls(
        &self,
        node: &Node,
        source: &str,
        temp_creations: &mut Vec<(usize, usize)>,
        has_cleanup: &mut bool,
    ) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func) = call.child_by_field_name("function") {
                let name = get_node_text(&func, source).trim().to_string();
                match name.as_str() {
                    "mkstemp" | "MKSTEMP" | "_mkstemp" | "mktemp" | "MKTEMP" | "_wmktemp"
                    | "mkdtemp" | "tmpnam" => {
                        temp_creations.push((
                            call.start_position().row + 1,
                            call.start_position().column + 1,
                        ));
                    }
                    "unlink" | "UNLINK" | "_unlink" | "_wunlink" | "remove" | "DeleteFile"
                    | "DeleteFileA" | "DeleteFileW" => {
                        *has_cleanup = true;
                    }
                    _ => {}
                }
            }
        }
    }
}

/// A plain `=`, not a compound assignment (`fd += 1` does not copy a handle).
fn is_plain_assignment(node: &Node) -> bool {
    node.child_by_field_name("operator")
        .is_some_and(|o| o.kind() == "=")
}

/// `expr` without enclosing parentheses: the lvalue `(f)` is `f`.
fn unwrap_held<'t>(expr: &Node<'t>) -> Node<'t> {
    let mut e = *expr;
    while e.kind() == "parenthesized_expression" {
        match e.named_child(0) {
            Some(inner) => e = inner,
            None => break,
        }
    }
    e
}

/// The identifier a declarator declares, through pointer, array and
/// parenthesized declarators (`*f`, `fds[2]`, `(*f)`).
fn declared_identifier<'t>(declarator: &Node<'t>) -> Option<Node<'t>> {
    let mut d = *declarator;
    loop {
        if d.kind() == "identifier" {
            return Some(d);
        }
        d = match d.child_by_field_name("declarator") {
            Some(inner) => inner,
            None => d.named_children(&mut d.walk()).find(|c| {
                matches!(
                    c.kind(),
                    "identifier" | "pointer_declarator" | "parenthesized_declarator"
                )
            })?,
        };
    }
}

/// Whether `ret` runs only where the open into `var` failed: a condition
/// already evaluated there pins `var` to its failure value (`!f`,
/// `f == NULL`, `fd < 0`, `fd == -1`, `h == INVALID_HANDLE_VALUE`, or the
/// negation of a success test on the other branch). Returning a failed
/// handle hands nothing over.
fn returned_on_failure(ret: &Node, var: &str, source: &str) -> bool {
    dominating_conditions_with_branches(ret)
        .into_iter()
        .any(|(cond, branch)| match branch {
            Some(taken) => failure_test(&cond, var, source) == Some(taken),
            None => false,
        })
}

/// `Some(true)` when `cond` holds exactly where `var` is the failed handle,
/// `Some(false)` when it holds exactly where it is a good one, `None` when
/// it is not such a test.
fn failure_test(cond: &Node, var: &str, source: &str) -> Option<bool> {
    let cond = unwrap_held(cond);
    let names_var = |n: &Node| {
        let n = unwrap_held(n);
        n.kind() == "identifier" && get_node_text(&n, source) == var
    };
    match cond.kind() {
        "identifier" if names_var(&cond) => Some(false),
        "unary_expression" => {
            let op = cond.child_by_field_name("operator")?;
            let arg = cond.child_by_field_name("argument")?;
            if get_node_text(&op, source) != "!" {
                return None;
            }
            if names_var(&arg) {
                return Some(true);
            }
            failure_test(&arg, var, source).map(|b| !b)
        }
        "binary_expression" => {
            let op = get_node_text(&cond.child_by_field_name("operator")?, source);
            let left = cond.child_by_field_name("left")?;
            let right = cond.child_by_field_name("right")?;
            let (other, var_on_left) = if names_var(&left) {
                (right, true)
            } else if names_var(&right) {
                (left, false)
            } else {
                return None;
            };
            let other = get_node_text(&unwrap_held(&other), source).replace(' ', "");
            let failure_value = matches!(
                other.as_str(),
                "NULL" | "0" | "-1" | "INVALID_HANDLE_VALUE" | "nullptr" | "((void*)0)"
            );
            match op {
                "==" if failure_value => Some(true),
                "!=" if failure_value => Some(false),
                "<" if var_on_left && other == "0" => Some(true),
                ">=" if var_on_left && other == "0" => Some(false),
                ">" if !var_on_left && other == "0" => Some(true),
                "<=" if !var_on_left && other == "0" => Some(false),
                _ => None,
            }
        }
        _ => None,
    }
}

/// `x` when `expr` is `&x`.
fn address_of_identifier<'t>(expr: &Node<'t>, source: &str) -> Option<Node<'t>> {
    if expr.kind() != "pointer_expression"
        || expr
            .child_by_field_name("operator")
            .is_none_or(|o| get_node_text(&o, source) != "&")
    {
        return None;
    }
    let operand = unwrap_held(&expr.child_by_field_name("argument")?);
    (operand.kind() == "identifier").then_some(operand)
}
