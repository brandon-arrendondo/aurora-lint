// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! ARR01-C: Do not apply the sizeof operator to a pointer when taking the size of an array
//!
//! This rule detects when `sizeof` is applied to array function parameters, which
//! have decayed to pointers. The sizeof operator on such parameters returns the
//! size of a pointer, not the size of the array.
//!
//! # Violation Patterns
//!
//! ```c
//! void function(int array[]) {
//!     size_t size = sizeof(array);  // VIOLATION: sizeof(int*), not sizeof(array)
//! }
//! ```
//!
//! ```c
//! void function(int array[10]) {
//!     size_t count = sizeof(array) / sizeof(array[0]);  // VIOLATION: still a pointer
//! }
//! ```
//!
//! # Compliant Solutions
//!
//! ```c
//! void function(int array[], size_t array_size) {
//!     // Pass size separately
//! }
//! ```
//!
//! ```c
//! int main() {
//!     int array[10];
//!     size_t size = sizeof(array);  // OK: array is a true array, not a parameter
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{
    extract_struct_name_from_type, find_containing_function, get_node_text,
    resolve_identifier_declarator,
};
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Arr01C;

impl CertRule for Arr01C {
    fn rule_id(&self) -> &'static str {
        "ARR01-C"
    }

    fn description(&self) -> &'static str {
        "Do not apply the sizeof operator to a pointer when taking the size of an array"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "ARR01-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Process each function definition separately to maintain proper scope
        self.check_function_definitions(node, source, &mut violations);

        // Also check for incomplete arrays (global scope)
        let mut incomplete_arrays = HashMap::new();
        self.collect_incomplete_arrays(node, source, &mut incomplete_arrays);
        self.check_sizeof_expressions(node, source, &incomplete_arrays, &mut violations);

        // sizeof on a flexible array member, resolved against the structs
        // this file defines rather than guessed from the member's name.
        let flexible = FlexibleArrayMembers::collect(node, source);
        if !flexible.is_empty() {
            self.check_flexible_array_sizeof(node, source, &flexible, &mut violations);
        }

        violations
    }
}

impl Arr01C {
    /// Recursively collect file-scope declarations, including inside preprocessor blocks.
    fn collect_file_scope_declarations<'a>(node: &Node<'a>, decls: &mut Vec<Node<'a>>) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "declaration" {
                    decls.push(child);
                } else if child.kind().starts_with("preproc_") {
                    Self::collect_file_scope_declarations(&child, decls);
                }
            }
        }
    }

    fn check_function_definitions(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for func_node in query::find_descendants_of_kind(*node, "function_definition") {
            // Collect parameters for this specific function
            let mut function_params = HashMap::new();
            if let Some(declarator) = func_node.child_by_field_name("declarator") {
                self.extract_array_params_from_declarator(
                    &declarator,
                    source,
                    &mut function_params,
                );
            }

            // Check sizeof expressions within this function's body
            if let Some(body) = func_node.child_by_field_name("body") {
                self.check_sizeof_expressions(&body, source, &function_params, violations);
            }
        }
    }

    /// Collect all function parameters (both array syntax and pointer types)
    /// These parameters may have decayed from arrays, making sizeof incorrect
    #[allow(dead_code)]
    fn collect_array_parameters(&self, node: &Node, source: &str) -> HashMap<String, usize> {
        let mut array_params = HashMap::new();
        self.collect_array_params_recursive(node, source, &mut array_params);
        self.collect_incomplete_arrays(node, source, &mut array_params);
        array_params
    }

    /// Collect incomplete array declarations (e.g., extern int arr[])
    /// Only collect arrays without size AND without initializer at global/file scope
    fn collect_incomplete_arrays(
        &self,
        node: &Node,
        source: &str,
        array_params: &mut HashMap<String, usize>,
    ) {
        // Check file-scope declarations, including those inside preprocessor blocks
        if node.kind() == "translation_unit" {
            let mut decls = Vec::new();
            Self::collect_file_scope_declarations(node, &mut decls);
            for child in &decls {
                self.check_global_declaration(child, source, array_params);
            }
        }
    }

    fn check_global_declaration(
        &self,
        node: &Node,
        source: &str,
        array_params: &mut HashMap<String, usize>,
    ) {
        // Only process if no initializer (incomplete array). The initializer
        // hangs off the `init_declarator`, not the `declaration`, so
        // `static const T name[] = { ... }` is a complete array whose size
        // the compiler infers -- sizeof on it is exactly right.
        if let Some(declarator) = node.child_by_field_name("declarator") {
            let has_initializer = declarator.kind() == "init_declarator";
            if !has_initializer {
                // Look for array declarators with no size
                if self.is_incomplete_array_declarator(&declarator) {
                    if let Some(name) = self.extract_param_name(&declarator, source) {
                        let line = node.start_position().row + 1;
                        array_params.insert(name, line);
                    }
                }
            }
        }
    }

    fn is_incomplete_array_declarator(&self, declarator: &Node) -> bool {
        // Check for array_declarator with empty size
        if declarator.kind() == "array_declarator" {
            // If size field is missing or empty, it's incomplete
            if declarator.child_by_field_name("size").is_none() {
                return true;
            }
        }

        // Check children recursively
        for i in 0..declarator.child_count() {
            if let Some(child) = declarator.child(i) {
                if self.is_incomplete_array_declarator(&child) {
                    return true;
                }
            }
        }

        false
    }

    #[allow(dead_code)]
    fn collect_array_params_recursive(
        &self,
        node: &Node,
        source: &str,
        array_params: &mut HashMap<String, usize>,
    ) {
        // Look for function definitions
        for func_node in query::find_descendants_of_kind(*node, "function_definition") {
            // Get the function declarator
            if let Some(declarator) = func_node.child_by_field_name("declarator") {
                self.extract_array_params_from_declarator(&declarator, source, array_params);
            }
        }
    }

    fn extract_array_params_from_declarator(
        &self,
        declarator: &Node,
        source: &str,
        array_params: &mut HashMap<String, usize>,
    ) {
        // Find parameters list
        if let Some(params_node) = self.find_parameters_node(declarator) {
            // Process each parameter
            for i in 0..params_node.child_count() {
                if let Some(param) = params_node.child(i) {
                    if param.kind() == "parameter_declaration" {
                        self.process_parameter_declaration(&param, source, array_params);
                    }
                }
            }
        }
    }

    fn find_parameters_node<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        // For function_declarator, parameters is a direct field
        if node.kind() == "function_declarator" {
            return node.child_by_field_name("parameters");
        }

        // Recursively search in child nodes
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "function_declarator" {
                    return child.child_by_field_name("parameters");
                }
                if let Some(found) = self.find_parameters_node(&child) {
                    return Some(found);
                }
            }
        }

        None
    }

    fn process_parameter_declaration(
        &self,
        param: &Node,
        source: &str,
        array_params: &mut HashMap<String, usize>,
    ) {
        // Get the declarator
        if let Some(declarator) = param.child_by_field_name("declarator") {
            // Check if it's an array declarator OR pointer declarator
            let is_array = self.is_array_declarator(&declarator);
            let is_pointer = self.is_pointer_declarator(&declarator);

            // Check if parameter type is a typedef'd array (e.g., typedef int arr[])
            let is_typedef_array = self.is_typedef_array_parameter(&param, source);

            if is_array || is_pointer || is_typedef_array {
                // Extract parameter name
                if let Some(param_name) = self.extract_param_name(&declarator, source) {
                    let line = param.start_position().row + 1;
                    array_params.insert(param_name, line);
                }
            }
        }
    }

    fn is_typedef_array_parameter(&self, param: &Node, source: &str) -> bool {
        // Check if the type specifier contains array brackets in typedef
        // Look for type_identifier that ends with array syntax
        if let Some(type_node) = param.child_by_field_name("type") {
            let type_text = get_node_text(&type_node, source);
            // If the type name suggests it's an array typedef (ends with _array, etc.)
            // or if we can detect it's a typedef to an incomplete array
            // This is a heuristic - ideally we'd track typedef definitions
            if type_text.contains("_array") || type_text.contains("Array") {
                return true;
            }
        }
        false
    }

    fn is_pointer_declarator(&self, declarator: &Node) -> bool {
        // Check if this is a pointer_declarator
        if declarator.kind() == "pointer_declarator" {
            return true;
        }

        // Check children
        for i in 0..declarator.child_count() {
            if let Some(child) = declarator.child(i) {
                if self.is_pointer_declarator(&child) {
                    return true;
                }
            }
        }

        false
    }

    fn is_array_declarator(&self, declarator: &Node) -> bool {
        // Check if this declarator or any child is an array_declarator
        if declarator.kind() == "array_declarator" {
            return true;
        }

        // Check children recursively
        for i in 0..declarator.child_count() {
            if let Some(child) = declarator.child(i) {
                if self.is_array_declarator(&child) {
                    return true;
                }
            }
        }

        false
    }

    fn extract_param_name(&self, declarator: &Node, source: &str) -> Option<String> {
        match declarator.kind() {
            "identifier" => Some(get_node_text(declarator, source).to_string()),
            "array_declarator" => {
                // The identifier is in the 'declarator' field of array_declarator
                if let Some(inner_declarator) = declarator.child_by_field_name("declarator") {
                    self.extract_param_name(&inner_declarator, source)
                } else {
                    None
                }
            }
            "pointer_declarator" => {
                // Handle pointer-to-array cases
                if let Some(inner_declarator) = declarator.child_by_field_name("declarator") {
                    self.extract_param_name(&inner_declarator, source)
                } else {
                    None
                }
            }
            _ => {
                // Search children
                for i in 0..declarator.child_count() {
                    if let Some(child) = declarator.child(i) {
                        if let Some(name) = self.extract_param_name(&child, source) {
                            return Some(name);
                        }
                    }
                }
                None
            }
        }
    }

    fn check_sizeof_expressions(
        &self,
        node: &Node,
        source: &str,
        array_params: &HashMap<String, usize>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for sizeof_expression nodes, and va_arg assignments that extract
        // pointers (pattern: int *arr = va_arg(args, int*); sizeof(arr);)
        for n in query::find_descendants_of_kinds(*node, &["sizeof_expression", "init_declarator"])
        {
            match n.kind() {
                "sizeof_expression" => {
                    self.check_sizeof_operand(&n, source, array_params, violations)
                }
                "init_declarator" => self.check_va_arg_assignment(&n, source),
                _ => {}
            }
        }
    }

    fn check_va_arg_assignment(&self, node: &Node, _source: &str) {
        // This is a placeholder for tracking va_arg pointers
        // We'll track these in the actual sizeof check
        if let Some(_value) = node.child_by_field_name("value") {
            // Check if value is a call to va_arg
            // We'll handle this in check_sizeof_operand
        }
    }

    fn check_sizeof_operand(
        &self,
        sizeof_node: &Node,
        source: &str,
        array_params: &HashMap<String, usize>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get the operand of sizeof
        if let Some(value_node) = sizeof_node.child_by_field_name("value") {
            // Only a bare parameter name measures the decayed pointer.
            // `sizeof(*p)`, `sizeof(p->member)`, `sizeof(p[0])` all measure
            // the pointee and are the idiomatic way to size through a pointer.
            let Some(operand) = Self::bare_identifier_operand(&value_node) else {
                return;
            };
            let var_names = vec![get_node_text(&operand, source).to_string()];

            // Check if any of these variables are array parameters
            for var_name in &var_names {
                if array_params.contains_key(var_name) {
                    // Verify this sizeof is within the same function where the parameter is declared
                    if self.is_sizeof_in_same_function(sizeof_node, var_name, array_params) {
                        let start_point = sizeof_node.start_position();
                        let sizeof_text = get_node_text(sizeof_node, source);

                        violations.push(RuleViolation {
                            rule_id: "ARR01-C".to_string(),
                            severity: Severity::High,
                            message: format!(
                                "sizeof applied to pointer/array parameter '{}' which has decayed to a pointer",
                                var_name
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(format!(
                                "Do not use '{}'. Array/pointer parameters decay to pointers. \
                                Pass the array size as a separate parameter instead.",
                                sizeof_text
                            )),
                            ..Default::default()
                        });
                        return; // Only report once per sizeof
                    }
                }
            }

            // Check if this variable was assigned from va_arg (pointer extraction)
            for var_name in &var_names {
                if self.is_va_arg_pointer(sizeof_node, var_name, source) {
                    let start_point = sizeof_node.start_position();
                    let sizeof_text = get_node_text(sizeof_node, source);

                    violations.push(RuleViolation {
                        rule_id: "ARR01-C".to_string(),
                        severity: Severity::High,
                        message: format!(
                            "sizeof applied to pointer '{}' extracted from va_arg",
                            var_name
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(format!(
                            "Do not use '{}' on pointers from va_arg. These are pointers, not arrays. \
                            Pass array size information separately.",
                            sizeof_text
                        )),
                        ..Default::default()
                    });
                    return;
                }
            }
        }
    }

    fn is_va_arg_pointer(&self, sizeof_node: &Node, var_name: &str, source: &str) -> bool {
        // Find the containing function
        if let Some(func_node) = find_containing_function(sizeof_node) {
            // Look for declaration of var_name in this function
            if let Some(body) = func_node.child_by_field_name("body") {
                return self.find_va_arg_declaration(&body, var_name, source);
            }
        }
        false
    }

    fn find_va_arg_declaration(&self, node: &Node, var_name: &str, source: &str) -> bool {
        // Look for: int *arr = va_arg(...)
        query::find_first_descendant(*node, |n| {
            n.kind() == "declaration"
                && n.child_by_field_name("declarator")
                    .is_some_and(|declarator| {
                        self.is_init_declarator_with_va_arg(&declarator, var_name, source)
                    })
        })
        .is_some()
    }

    fn is_init_declarator_with_va_arg(
        &self,
        declarator: &Node,
        var_name: &str,
        source: &str,
    ) -> bool {
        if declarator.kind() == "init_declarator" {
            // Check if declarator name matches
            if let Some(decl_node) = declarator.child_by_field_name("declarator") {
                if let Some(name) = self.extract_param_name(&decl_node, source) {
                    if name == var_name {
                        // Check if value is va_arg call
                        if let Some(value) = declarator.child_by_field_name("value") {
                            return self.is_va_arg_call(&value, source);
                        }
                    }
                }
            }
        }

        // Check children
        for i in 0..declarator.child_count() {
            if let Some(child) = declarator.child(i) {
                if self.is_init_declarator_with_va_arg(&child, var_name, source) {
                    return true;
                }
            }
        }

        false
    }

    fn is_va_arg_call(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                let func_name = get_node_text(&func, source);
                if func_name == "va_arg" {
                    return true;
                }
            }
        }

        // Check children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if self.is_va_arg_call(&child, source) {
                    return true;
                }
            }
        }

        false
    }

    /// Report `sizeof(x->member)` / `sizeof(x.member)` where `member` is a
    /// flexible array member of a struct defined in this file.
    fn check_flexible_array_sizeof(
        &self,
        node: &Node,
        source: &str,
        flexible: &FlexibleArrayMembers,
        violations: &mut Vec<RuleViolation>,
    ) {
        for sizeof_node in query::find_descendants_of_kind(*node, "sizeof_expression") {
            let Some(value) = sizeof_node.child_by_field_name("value") else {
                continue;
            };
            let mut operand = value;
            while operand.kind() == "parenthesized_expression" {
                match operand.named_child(0) {
                    Some(inner) => operand = inner,
                    None => break,
                }
            }
            if operand.kind() != "field_expression" {
                continue;
            }
            if !flexible.is_flexible_access(&operand, source) {
                continue;
            }
            let start_point = sizeof_node.start_position();
            let sizeof_text = get_node_text(&sizeof_node, source);
            violations.push(RuleViolation {
                rule_id: "ARR01-C".to_string(),
                severity: Severity::High,
                message: "sizeof applied to flexible array member".to_string(),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some(format!(
                    "Do not use '{}' on flexible array members. \
                    Flexible array members have indeterminate size.",
                    sizeof_text
                )),
                ..Default::default()
            });
        }
    }

    /// The identifier when the sizeof operand is a (possibly parenthesized)
    /// bare identifier; `None` for any dereference, member access, subscript
    /// or other expression, whose size is not the pointer's.
    fn bare_identifier_operand<'a>(node: &Node<'a>) -> Option<Node<'a>> {
        let mut cur = *node;
        while cur.kind() == "parenthesized_expression" {
            cur = cur.named_child(0)?;
        }
        (cur.kind() == "identifier").then_some(cur)
    }

    fn is_sizeof_in_same_function(
        &self,
        sizeof_node: &Node,
        param_name: &str,
        array_params: &HashMap<String, usize>,
    ) -> bool {
        // Find the containing function
        if let Some(_func_node) = find_containing_function(sizeof_node) {
            // If we found the parameter in our map, and we're in a function,
            // assume they're in the same scope (this is a simplification)
            // A more robust check would compare function boundaries
            array_params.contains_key(param_name)
        } else {
            false
        }
    }
}

/// The flexible array members declared by the structs in one file: the last
/// `field_declaration` of a struct body whose array declarator has no size.
/// Keyed by struct tag and by every typedef alias of the same body.
struct FlexibleArrayMembers {
    by_struct: HashMap<String, HashSet<String>>,
    /// Member names that are a flexible array in at least one struct here.
    flexible_names: HashSet<String>,
    /// Member names declared as anything else in at least one struct here.
    other_names: HashSet<String>,
}

impl FlexibleArrayMembers {
    fn collect(root: &Node, source: &str) -> Self {
        let mut this = Self {
            by_struct: HashMap::new(),
            flexible_names: HashSet::new(),
            other_names: HashSet::new(),
        };
        for spec in query::find_descendants_of_kind(*root, "struct_specifier") {
            let Some(body) = spec.child_by_field_name("body") else {
                continue;
            };
            let fields: Vec<Node> = (0..body.named_child_count())
                .filter_map(|i| body.named_child(i))
                .filter(|f| f.kind() == "field_declaration")
                .collect();
            let Some(last) = fields.last() else {
                continue;
            };
            let flexible_member = Self::unsized_array_member(last, source);
            for f in &fields[..fields.len() - 1] {
                if let Some(name) = Self::member_name(f, source) {
                    this.other_names.insert(name);
                }
            }
            let Some(member) = flexible_member else {
                if let Some(name) = Self::member_name(last, source) {
                    this.other_names.insert(name);
                }
                continue;
            };
            this.flexible_names.insert(member.clone());
            let mut names: Vec<String> = spec
                .child_by_field_name("name")
                .map(|n| get_node_text(&n, source).to_string())
                .into_iter()
                .collect();
            // `typedef struct [tag] { ... } alias;` -- the aliases are the
            // type_identifier children of the enclosing type_definition.
            if let Some(parent) = spec.parent() {
                if parent.kind() == "type_definition" {
                    names.extend(
                        (0..parent.named_child_count())
                            .filter_map(|i| parent.named_child(i))
                            .filter(|c| c.kind() == "type_identifier")
                            .map(|c| get_node_text(&c, source).to_string()),
                    );
                }
            }
            for name in names {
                this.by_struct
                    .entry(name)
                    .or_default()
                    .insert(member.clone());
            }
        }
        this
    }

    fn is_empty(&self) -> bool {
        self.flexible_names.is_empty()
    }

    /// The member name if `field` is `T name[];` (an array declarator with no
    /// size and no pointer in between).
    fn unsized_array_member(field: &Node, source: &str) -> Option<String> {
        let decl = field.child_by_field_name("declarator")?;
        if decl.kind() != "array_declarator" || decl.child_by_field_name("size").is_some() {
            return None;
        }
        let inner = decl.child_by_field_name("declarator")?;
        (inner.kind() == "field_identifier").then(|| get_node_text(&inner, source).to_string())
    }

    fn member_name(field: &Node, source: &str) -> Option<String> {
        let mut decl = field.child_by_field_name("declarator")?;
        loop {
            match decl.kind() {
                "field_identifier" => return Some(get_node_text(&decl, source).to_string()),
                "array_declarator"
                | "pointer_declarator"
                | "function_declarator"
                | "parenthesized_declarator" => {
                    decl = decl
                        .child_by_field_name("declarator")
                        .or_else(|| decl.named_child(0))?;
                }
                _ => return None,
            }
        }
    }

    /// Whether `expr` (a `field_expression`) reads a flexible array member.
    /// Resolves the base variable's declared struct type when it is a plain
    /// identifier; otherwise falls back to the member name, which counts only
    /// when no struct in this file declares a fixed member of that name.
    fn is_flexible_access(&self, expr: &Node, source: &str) -> bool {
        let Some(field) = expr.child_by_field_name("field") else {
            return false;
        };
        let member = get_node_text(&field, source);
        if !self.flexible_names.contains(member) {
            return false;
        }
        if let Some(arg) = expr.child_by_field_name("argument") {
            if arg.kind() == "identifier" {
                let name = get_node_text(&arg, source);
                if let Some((decl, _)) = resolve_identifier_declarator(&arg, name, source) {
                    if let Some(ty) = decl.child_by_field_name("type") {
                        let ty_text = get_node_text(&ty, source);
                        return match extract_struct_name_from_type(ty_text)
                            .or_else(|| Some(ty_text.trim()))
                            .and_then(|s| self.by_struct.get(s))
                        {
                            Some(members) => members.contains(member),
                            // A struct this file does not define: only the
                            // name is left to go on.
                            None => !self.other_names.contains(member),
                        };
                    }
                }
            }
        }
        !self.other_names.contains(member)
    }
}
