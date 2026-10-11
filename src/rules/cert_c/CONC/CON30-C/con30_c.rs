// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! CON30-C: Clean up thread-specific storage
//!
//! Thread-specific storage (TSS) must be properly freed to avoid memory leaks.
//! When storing allocated memory under a key, ensure either:
//! 1. A destructor is registered when the key is created
//!    (`tss_create(&key, destructor)`), OR
//! 2. Memory is explicitly freed via `free(tss_get(key))` before thread exit
//!
//! The hazard is read API-neutrally (`docs/design/thread-api-families.md`):
//! C11's `tss_*`, POSIX's `pthread_key_create`/`pthread_setspecific`/
//! `pthread_getspecific`, and declared families, through
//! `thread_api::thread_op`. A family whose storage is fixed slots with no key
//! creation (FreeRTOS's thread-local storage pointers) has no destructor to
//! register, unless its store call takes one, so a slot stored into anywhere
//! in the file and never freed through its get call is reported at the
//! store.
//!
//! Only a store that may hold allocated memory counts: a null pointer
//! (clearing the key), an address taken with `&`, a string literal, or a
//! name declared as an array or a function holds nothing to free. The free
//! is any deallocator's (`call_roles::freed_argument`): `free`, a declared
//! one, or a selected profile's kernel heap (FreeRTOS's `vPortFree`).
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! tss_create(&key, NULL);  // No destructor
//! int *data = malloc(sizeof(int));
//! tss_set(key, data);      // Memory leak - never freed
//! ```
//!
//! **Compliant (Destructor):**
//! ```c
//! tss_create(&key, free);  // Destructor registered
//! ```
//!
//! **Compliant (Explicit):**
//! ```c
//! free(tss_get(key));      // Explicit cleanup before thread exit
//! ```

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::analyze::init_state::strip_arg_casts;
use crate::analyze::side_effects::is_null_pointer_constant;
use crate::manifest::Severity;
use crate::settings::threads::{Role, ThreadOpKind, ThreadTypeKind};
use crate::utility::cert_c::ast_utils::{get_node_text, resolve_identifier_declarator};
use crate::utility::cert_c::call_roles;
use crate::utility::cert_c::node_children::NodeChildren;
use crate::utility::cert_c::thread_api::{self, Family, ProjectFunctions};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

#[derive(Default)]
pub struct Con30C {
    /// The project's function definitions in every scanned file, for a
    /// library name the project defines itself.
    project: RefCell<Option<ProjectFunctions>>,
}

/// Tracks TSS key information
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct TssKeyInfo {
    key_name: String,
    has_destructor: bool,
    create_line: usize,
    create_column: usize,
    /// The family whose call created the key, for the message.
    family: Family,
    /// The creating call's name.
    create_name: String,
}

/// A store into a fixed slot of a family with no key creation.
#[derive(Debug, Clone)]
struct SlotStore {
    family: Family,
    set_name: String,
    has_destructor: bool,
    line: usize,
    column: usize,
}

impl CertRule for Con30C {
    fn rule_id(&self) -> &'static str {
        "CON30-C"
    }

    fn description(&self) -> &'static str {
        "Clean up thread-specific storage"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "CON30-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.function_summaries.clone());
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // A `tss_t key;` declared at file scope is genuinely shared by every
        // function that touches it, so those keys are correctly analyzed by
        // aggregating call sites across the whole translation unit.
        let global_keys = self.collect_global_tss_key_names(node, source);

        let mut tss_keys: HashMap<String, TssKeyInfo> = HashMap::new();
        let mut tss_set_calls: HashSet<String> = HashSet::new();
        let mut tss_get_freed: HashSet<String> = HashSet::new();
        self.analyze_tss_operations(
            node,
            source,
            &mut tss_keys,
            &mut tss_set_calls,
            &mut tss_get_freed,
            Some(&global_keys),
        );
        self.collect_violations(&tss_keys, &tss_set_calls, &tss_get_freed, &mut violations);
        self.collect_slot_violations(node, source, &mut violations);

        // A `tss_t key;` declared *inside* a function is a distinct object
        // from a same-named local in another function. Give each function
        // its own fresh scope so that one function's proper cleanup
        // (tss_create/tss_set/free(tss_get(...))) can never mask a real
        // leak of a same-named key local to a different function.
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            let mut local_keys: HashMap<String, TssKeyInfo> = HashMap::new();
            let mut local_set_calls: HashSet<String> = HashSet::new();
            let mut local_get_freed: HashSet<String> = HashSet::new();
            self.analyze_tss_operations(
                &func,
                source,
                &mut local_keys,
                &mut local_set_calls,
                &mut local_get_freed,
                None,
            );
            // Keys that are actually file-scope were already handled above
            // by the whole-translation-unit pass; don't double-report them.
            local_keys.retain(|k, _| !global_keys.contains(k));
            local_set_calls.retain(|k| !global_keys.contains(k));
            local_get_freed.retain(|k| !global_keys.contains(k));
            self.collect_violations(
                &local_keys,
                &local_set_calls,
                &local_get_freed,
                &mut violations,
            );
        }

        violations
    }
}

impl Con30C {
    /// Generate violations for keys with tss_set but no destructor and no
    /// explicit free. Shared between the file-scope (global keys) pass and
    /// the per-function (local keys) passes in `check`.
    fn collect_violations(
        &self,
        tss_keys: &HashMap<String, TssKeyInfo>,
        tss_set_calls: &HashSet<String>,
        tss_get_freed: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for (key_name, key_info) in tss_keys {
            let set_name = key_info
                .family
                .function_of(ThreadOpKind::TssSet)
                .unwrap_or_else(|| "tss_set".to_string());
            let get_name = key_info
                .family
                .function_of(ThreadOpKind::TssGet)
                .unwrap_or_else(|| "tss_get".to_string());
            let create_name = &key_info.create_name;
            // If tss_set was called for this key
            if tss_set_calls.contains(key_name) {
                // And no destructor was registered
                if !key_info.has_destructor {
                    // And tss_get result wasn't freed
                    if !tss_get_freed.contains(key_name) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            message: format!(
                                "Thread-specific storage key '{key_name}' created without \
                                 destructor and memory stored via {set_name}() is never freed. \
                                 Register a destructor in {create_name}() or explicitly \
                                 free({get_name}({key_name}))."
                            ),
                            severity: self.severity(),
                            line: key_info.create_line,
                            column: key_info.create_column,
                            file_path: String::new(),
                            suggestion: Some(format!(
                                "Either register a destructor: {create_name}(&{key_name}, free) \
                                 or explicitly cleanup: free({get_name}({key_name}))"
                            )),
                            requires_manual_review: None,
                        });
                    }
                }
            }
        }
    }

    /// Collect the names of `tss_t` variables declared directly at file
    /// scope (i.e. direct children of the translation unit, not inside any
    /// function body). These are genuinely shared across every function
    /// that references them, so it's correct to aggregate their call sites
    /// across the whole translation unit. Locals declared inside a function
    /// body are a different object per function and must not be merged
    /// with this set.
    fn collect_global_tss_key_names(&self, node: &Node, source: &str) -> HashSet<String> {
        let mut names = HashSet::new();
        for child in node.child_nodes() {
            if child.kind() != "declaration" {
                continue;
            }
            let is_tss_t = child
                .child_by_field_name("type")
                .and_then(|t| thread_api::type_kind(get_node_text(&t, source).trim()))
                == Some(ThreadTypeKind::TssKey);
            if !is_tss_t {
                continue;
            }
            for j in 0..child.child_count() {
                if child.field_name_for_child(j as u32) == Some("declarator") {
                    if let Some(declarator) = child.child(j) {
                        if let Some(name) = self.declarator_identifier(&declarator, source) {
                            names.insert(name);
                        }
                    }
                }
            }
        }
        names
    }

    /// Recover the identifier being declared by a (possibly wrapped)
    /// declarator node, e.g. `key` in `tss_t key;` or `tss_t key =
    /// TSS_DTOR_ITERATIONS;`.
    fn declarator_identifier(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source).to_string());
        }
        if let Some(inner) = node.child_by_field_name("declarator") {
            return self.declarator_identifier(&inner, source);
        }
        query::find_first_descendant(*node, |n| n.kind() == "identifier")
            .map(|n| get_node_text(&n, source).to_string())
    }

    /// Analyze the AST for TSS operations. When `allowed` is `Some(set)`,
    /// only keys whose name is in `set` are recorded (used for the
    /// file-scope pass so it stays limited to genuinely-global keys); when
    /// `None`, every key encountered under `node` is recorded (used for a
    /// single function's own scope).
    fn analyze_tss_operations(
        &self,
        node: &Node,
        source: &str,
        tss_keys: &mut HashMap<String, TssKeyInfo>,
        tss_set_calls: &mut HashSet<String>,
        tss_get_freed: &mut HashSet<String>,
        allowed: Option<&HashSet<String>>,
    ) {
        let is_allowed = |key_name: &str| allowed.is_none_or(|set| set.contains(key_name));
        let project = self.project.borrow();

        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(op) = thread_api::thread_op(&call, source, project.as_ref()) {
                match op.kind() {
                    ThreadOpKind::TssCreate => {
                        if let Some(key_name) = op.operand(Role::Key).map(|k| key_text(&k, source))
                        {
                            if is_allowed(&key_name) {
                                let has_destructor = op
                                    .operand(Role::Destructor)
                                    .is_some_and(|d| is_destructor(&d, source));
                                tss_keys.insert(
                                    key_name.clone(),
                                    TssKeyInfo {
                                        key_name,
                                        has_destructor,
                                        create_line: call.start_position().row + 1,
                                        create_column: call.start_position().column + 1,
                                        family: op.family,
                                        create_name: op.name.clone(),
                                    },
                                );
                            }
                        }
                    }
                    ThreadOpKind::TssSet
                        if op.family.creates_storage_keys()
                            && op
                                .operand(Role::Value)
                                .is_none_or(|v| may_hold_allocation(&v, source)) =>
                    {
                        if let Some(key_name) = op.operand(Role::Key).map(|k| key_text(&k, source))
                        {
                            if is_allowed(&key_name) {
                                tss_set_calls.insert(key_name);
                            }
                        }
                    }
                    _ => {}
                }
                continue;
            }
            // free(tss_get(key)), or any deallocator's.
            if let Some(key_name) = self.freed_storage_key(&call, source, project.as_ref()) {
                if is_allowed(&key_name) {
                    tss_get_freed.insert(key_name);
                }
            }
        }
    }

    /// The key or slot whose stored value `call` frees: `free(tss_get(key))`,
    /// or any deallocator's freed argument holding a storage get call.
    fn freed_storage_key(
        &self,
        call: &Node,
        source: &str,
        project: Option<&ProjectFunctions>,
    ) -> Option<String> {
        let freed = call_roles::freed_argument(call, source)?;
        let get_call = query::find_first_descendant(freed, |n| {
            n.kind() == "call_expression"
                && thread_api::thread_op_of_kind(&n, source, project, ThreadOpKind::TssGet)
                    .is_some()
        })?;
        let get = thread_api::thread_op(&get_call, source, project)?;
        get.operand(Role::Key).map(|k| key_text(&k, source))
    }

    /// Report each store into a fixed slot (a family with no key creation,
    /// so no destructor) when nothing in the file frees that slot through
    /// its get call and the store carries no destructor of its own. A slot
    /// belongs to the task, not to one function, so the whole translation
    /// unit is one scope.
    fn collect_slot_violations(
        &self,
        root: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let project = self.project.borrow();
        let project = project.as_ref();
        let mut stores: Vec<(String, SlotStore)> = Vec::new();
        let mut freed: HashSet<String> = HashSet::new();
        for call in query::find_descendants_of_kind(*root, "call_expression") {
            if let Some(op) =
                thread_api::thread_op_of_kind(&call, source, project, ThreadOpKind::TssSet)
            {
                let holds_allocation = op
                    .operand(Role::Value)
                    .is_none_or(|v| may_hold_allocation(&v, source));
                if op.family.creates_storage_keys() || !holds_allocation {
                    continue;
                }
                if let Some(slot) = op.operand(Role::Key).map(|k| key_text(&k, source)) {
                    stores.push((
                        slot,
                        SlotStore {
                            family: op.family,
                            set_name: op.name.clone(),
                            has_destructor: op
                                .operand(Role::Destructor)
                                .is_some_and(|d| is_destructor(&d, source)),
                            line: call.start_position().row + 1,
                            column: call.start_position().column + 1,
                        },
                    ));
                }
                continue;
            }
            if let Some(slot) = self.freed_storage_key(&call, source, project) {
                freed.insert(slot);
            }
        }
        for (slot, store) in stores {
            if store.has_destructor || freed.contains(&slot) {
                continue;
            }
            let get_name = store
                .family
                .function_of(ThreadOpKind::TssGet)
                .unwrap_or_else(|| "the slot's get call".to_string());
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                message: format!(
                    "Thread-local storage slot {slot} is stored into with {}() and never freed; \
                     no destructor cleans the slot up at thread exit. Free it explicitly \
                     before the thread ends: free({get_name}(..., {slot})).",
                    store.set_name
                ),
                severity: self.severity(),
                line: store.line,
                column: store.column,
                file_path: String::new(),
                suggestion: Some(format!(
                    "Free the stored value before the thread ends: free({get_name}(..., {slot}))"
                )),
                requires_manual_review: None,
            });
        }
    }
}

/// A key operand's name: `key` for `key` and for `&key`.
fn key_text(arg: &Node, source: &str) -> String {
    let text = get_node_text(arg, source).trim();
    text.strip_prefix('&')
        .map_or_else(|| text.to_string(), |s| s.trim().to_string())
}

/// Whether a destructor operand names one: not a null pointer constant,
/// casts aside (`(void *)0` is none).
fn is_destructor(arg: &Node, source: &str) -> bool {
    !is_null_pointer_constant(arg, source) && !get_node_text(arg, source).trim().is_empty()
}

/// Whether a stored value may be memory the thread allocated, so that it
/// needs freeing: not a null pointer constant (that clears the key), not an
/// address taken with `&`, not a literal, and not a name declared as an
/// array or a function. A pointer the file cannot place (a variable, a
/// call's result) may be.
fn may_hold_allocation(value: &Node, source: &str) -> bool {
    if is_null_pointer_constant(value, source) {
        return false;
    }
    let value = strip_arg_casts(value);
    match value.kind() {
        "pointer_expression" => value
            .child_by_field_name("operator")
            .is_none_or(|op| get_node_text(&op, source) != "&"),
        "string_literal" | "concatenated_string" | "number_literal" | "char_literal" => false,
        "identifier" => {
            let name = get_node_text(&value, source);
            match resolve_identifier_declarator(&value, name, source) {
                // An array parameter is a pointer.
                Some((decl, declarator)) => match declarator.kind() {
                    "array_declarator" => decl.kind() == "parameter_declaration",
                    "function_declarator" => false,
                    _ => true,
                },
                None => true,
            }
        }
        _ => true,
    }
}
