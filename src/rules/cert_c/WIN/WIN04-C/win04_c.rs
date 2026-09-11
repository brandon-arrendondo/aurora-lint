//! WIN04-C: Consider encrypting function pointers
//!
//! This rule detects function pointers that are stored without encryption,
//! which could be exploited by attackers if memory is overwritten.
//!
//! VIOLATIONS:
//! - Function pointer declarations initialized directly without EncodePointer
//! - A `GetProcAddress` result stored raw -- by assignment to an
//!   already-declared pointer, by a typedef'd declaration, or by a macro
//!   body -- without EncodePointer (task 1132)
//!
//! COMPLIANT:
//! - Function pointers stored using EncodePointer() or EncodeSystemPointer()
//! - Function pointers that are const or otherwise protected
//!
//! The assignment shape is deliberately narrow. This is a Recommendation
//! at High severity, and every function-pointer assignment in a program
//! would be noise; a `GetProcAddress` result is the one right-hand side
//! that is a function pointer by definition AND the exact "resolve at run
//! time, keep in a global" pattern the recommendation is about
//! (Ventoy2Disk's `FormatEx = (PFORMATEX)GetProcAddress(...)`, which the
//! declaration-only walk never saw). A store is left alone when the same
//! function later hands that pointer to EncodePointer -- the raw store was
//! a step, not the resting place.

use super::super::{CertRule, RuleViolation};
use crate::analyze::init_state::strip_arg_casts;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::overflow_helpers::enclosing_function_definition;
use lang_parsing_substrate::query;
use tree_sitter::Node;

/// The Win32 run-time symbol resolver. Its result is a function pointer by
/// definition (`FARPROC`), whatever it is cast to. No A/W variants exist.
const RUNTIME_RESOLVER: &str = "GetProcAddress";

pub struct Win04C;

// Functions that properly encode/encrypt function pointers
const ENCODE_FUNCS: &[&str] = &["EncodePointer", "EncodeSystemPointer"];
// Functions that decode encrypted pointers (acceptable for initialization)
const DECODE_FUNCS: &[&str] = &["DecodePointer", "DecodeSystemPointer"];

impl CertRule for Win04C {
    fn rule_id(&self) -> &'static str {
        "WIN04-C"
    }

    fn description(&self) -> &'static str {
        "Consider encrypting function pointers"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "WIN04-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Win04C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check declarations with function pointer types
        for decl in query::find_descendants_of_kind(*node, "declaration") {
            self.check_declaration(&decl, source, violations);
        }
        // A GetProcAddress result kept raw, whatever syntax stores it.
        for assign in query::find_descendants_of_kind(*node, "assignment_expression") {
            let (Some(lhs), Some(rhs)) = (
                assign.child_by_field_name("left"),
                assign.child_by_field_name("right"),
            ) else {
                continue;
            };
            self.check_resolver_store(&assign, &lhs, &rhs, source, violations);
        }
        for init in query::find_descendants_of_kind(*node, "init_declarator") {
            let (Some(lhs), Some(rhs)) = (
                init.child_by_field_name("declarator"),
                init.child_by_field_name("value"),
            ) else {
                continue;
            };
            self.check_resolver_store(&init, &lhs, &rhs, source, violations);
        }
        for def in query::find_descendants_of_kinds(*node, &["preproc_function_def", "preproc_def"])
        {
            self.check_macro_body(&def, source, violations);
        }
    }

    /// `lhs = (T)GetProcAddress(...)` / `T lhs = (T)GetProcAddress(...)`:
    /// report unless the store is encoded in place or `lhs` is handed to
    /// EncodePointer later in the same function. A declaration the
    /// function-pointer-typed walk already reported (its initializer is a
    /// GetProcAddress call it did not recognise as encoding) is skipped so
    /// one store yields one finding.
    fn check_resolver_store(
        &self,
        store: &Node,
        lhs: &Node,
        rhs: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if !self.is_resolver_call(rhs, source) || self.uses_encode_function(rhs, source) {
            return;
        }
        if store.kind() == "init_declarator" {
            let already_reported = store
                .parent()
                .is_some_and(|decl| self.is_function_pointer_declaration(&decl, source));
            if already_reported {
                return;
            }
        }
        let stored_name = get_node_text(&strip_arg_casts(lhs), source);
        if self.encoded_later_in_function(store, stored_name, source) {
            return;
        }
        let pos = store.start_position();
        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::High,
            message: format!(
                "GetProcAddress result stored in '{}' without encryption; consider using EncodePointer()",
                stored_name
            ),
            file_path: String::new(),
            line: pos.row + 1,
            column: pos.column + 1,
            suggestion: Some(
                "Use EncodePointer() to encrypt the function pointer before storage".to_string(),
            ),
            ..Default::default()
        });
    }

    /// `expr`, stripped of casts and parentheses, is a call to
    /// [`RUNTIME_RESOLVER`].
    fn is_resolver_call(&self, expr: &Node, source: &str) -> bool {
        let inner = strip_arg_casts(expr);
        inner.kind() == "call_expression"
            && inner
                .child_by_field_name("function")
                .is_some_and(|f| get_node_text(&f, source) == RUNTIME_RESOLVER)
    }

    /// Somewhere after `store` in the same function body, `name` (possibly
    /// cast) is an argument of an EncodePointer/EncodeSystemPointer call --
    /// the raw store was transient. A file-scope store has no enclosing
    /// function and is never excused this way.
    fn encoded_later_in_function(&self, store: &Node, name: &str, source: &str) -> bool {
        let Some(func) = enclosing_function_definition(store) else {
            return false;
        };
        let Some(body) = func.child_by_field_name("body") else {
            return false;
        };
        query::find_descendants_of_kind(body, "call_expression")
            .into_iter()
            .filter(|call| call.start_byte() > store.end_byte())
            .filter(|call| {
                call.child_by_field_name("function")
                    .is_some_and(|f| ENCODE_FUNCS.contains(&get_node_text(&f, source)))
            })
            .any(|call| {
                call.child_by_field_name("arguments").is_some_and(|args| {
                    let mut cursor = args.walk();
                    let matched = args
                        .named_children(&mut cursor)
                        .any(|arg| get_node_text(&strip_arg_casts(&arg), source) == name);
                    matched
                })
            })
    }

    /// A `#define` whose replacement text assigns a GetProcAddress result
    /// (`x = (T)GetProcAddress(...)`, `=` not `==`) with no EncodePointer in
    /// the same body: every expansion is a raw store, so the definition is
    /// reported once rather than each use. Text-level on purpose -- these
    /// helpers (Ventoy2Disk's `PF_INIT(proc, name)`) paste with `##`/`#`,
    /// which the expansion engine leaves alone.
    fn check_macro_body(&self, def: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let Some(value) = def.child_by_field_name("value") else {
            return;
        };
        let body = get_node_text(&value, source);
        let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
        // Whole-identifier match: `osGetProcAddressA` (sqlite's syscall
        // table wrapper) is not the resolver.
        let Some(call_at) = body.match_indices(RUNTIME_RESOLVER).find_map(|(at, _)| {
            let before = body[..at].chars().last().is_some_and(is_ident);
            let after = body[at + RUNTIME_RESOLVER.len()..]
                .chars()
                .next()
                .is_some_and(is_ident);
            (!before && !after).then_some(at)
        }) else {
            return;
        };
        let assigned = body[..call_at]
            .rfind('=')
            .is_some_and(|eq| !matches!(body[..eq].chars().last(), Some('=' | '!' | '<' | '>')));
        if !assigned || ENCODE_FUNCS.iter().any(|f| body.contains(f)) {
            return;
        }
        let name = def
            .child_by_field_name("name")
            .map(|n| get_node_text(&n, source))
            .unwrap_or("");
        let pos = def.start_position();
        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::High,
            message: format!(
                "Macro '{}' stores a GetProcAddress result without encryption at every expansion; consider using EncodePointer()",
                name
            ),
            file_path: String::new(),
            line: pos.row + 1,
            column: pos.column + 1,
            suggestion: Some(
                "Use EncodePointer() to encrypt the function pointer before storage".to_string(),
            ),
            ..Default::default()
        });
    }

    fn check_declaration(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check if this is a function pointer declaration
        if !self.is_function_pointer_declaration(node, source) {
            return;
        }

        // Check if there's an init_declarator with an initializer
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "init_declarator" {
                    // Check if the initializer uses EncodePointer
                    if let Some(initializer) = self.get_initializer(&child, source) {
                        if !self.uses_encode_function(&initializer, source) {
                            // Violation: function pointer initialized without encoding
                            let pos = child.start_position();
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::High,
                                message: "Function pointer stored without encryption; consider using EncodePointer()".to_string(),
                                file_path: String::new(),
                                line: pos.row + 1,
                                column: pos.column + 1,
                                suggestion: Some(
                                    "Use EncodePointer() to encrypt the function pointer before storage".to_string()
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    fn is_function_pointer_declaration(&self, node: &Node, source: &str) -> bool {
        // Check if declaration contains function pointer syntax
        let decl_text = get_node_text(node, source);

        // Function pointer patterns: (*name)( or (* name)(
        if decl_text.contains("(*") && decl_text.contains(")(") {
            return true;
        }

        // Also check for function_declarator within pointer_declarator
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if self.contains_function_pointer(&child) {
                    return true;
                }
            }
        }

        false
    }

    fn contains_function_pointer(&self, node: &Node) -> bool {
        let kind = node.kind();

        if kind == "function_declarator" {
            // Check if parent chain includes pointer_declarator
            return true;
        }

        // Check for pointer_declarator containing function_declarator
        if kind == "pointer_declarator" {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "function_declarator" {
                        return true;
                    }
                    if self.contains_function_pointer(&child) {
                        return true;
                    }
                }
            }
        }

        if kind == "init_declarator" || kind == "parenthesized_declarator" {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if self.contains_function_pointer(&child) {
                        return true;
                    }
                }
            }
        }

        false
    }

    fn get_initializer<'a>(&self, init_decl: &'a Node<'a>, _source: &str) -> Option<Node<'a>> {
        // Find the initializer value (after '=')
        let mut found_eq = false;
        for i in 0..init_decl.child_count() {
            if let Some(child) = init_decl.child(i) {
                if child.kind() == "=" {
                    found_eq = true;
                    continue;
                }
                if found_eq {
                    return Some(child);
                }
            }
        }
        None
    }

    fn uses_encode_function(&self, node: &Node, source: &str) -> bool {
        // Check if this node or any descendant is a call to an encode/decode function
        // (handles casts wrapping function calls too, since the whole subtree is searched)
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(func) = n.child_by_field_name("function") else {
                return false;
            };
            let func_name = get_node_text(&func, source);
            // Both encode (for storage) and decode (for use) are acceptable
            ENCODE_FUNCS.contains(&func_name) || DECODE_FUNCS.contains(&func_name)
        })
        .is_some()
    }
}
