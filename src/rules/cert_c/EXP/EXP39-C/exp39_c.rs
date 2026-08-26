//! EXP39-C: Do not access a variable through a pointer of an incompatible type
//!
//! This rule detects pointer casts to incompatible types, which can lead to undefined
//! behavior. Accessing an object through a pointer of an incompatible type violates
//! the strict aliasing rules and can cause unpredictable results.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! void f(void) {
//!   float f = 0.0f;
//!   int *ip = (int *)&f;  // Incompatible type cast
//!   (*ip)++;  // Undefined behavior
//! }
//! ```
//!
//! **Non-compliant (array dimension mismatch):**
//! ```c
//! void func(void) {
//!   int a[10][15];
//!   int (*b)[10] = a;  // Wrong second dimension
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! #include <math.h>
//! void f(void) {
//!   float f = 0.0f;
//!   f = nextafterf(f, FLT_MAX);  // Use standard library functions
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find cast_expression nodes that cast pointers
//! - Extract source and target pointer types
//! - Check if types are incompatible (e.g., float* to int*, short* to int*)
//! - Flag violations for known incompatible type combinations
//! - Exceptions: char/unsigned char types are allowed (strict aliasing exception)

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Exp39C;

/// Collected variable type information
#[derive(Debug, Clone)]
struct VarTypeInfo {
    base_type: String,
    is_array: bool,
    array_dimensions: Vec<String>, // e.g., ["ROWS", "COLS"] for int a[ROWS][COLS]
}

impl CertRule for Exp39C {
    fn rule_id(&self) -> &'static str {
        "EXP39-C"
    }

    fn description(&self) -> &'static str {
        "Do not access a variable through a pointer of an incompatible type"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "EXP39-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Collect file-scope declarations first (variables/unions declared
        // outside any function body). These are genuinely shared across
        // every function that references them, so it is correct to merge
        // their accesses into a single bucket.
        let mut global_var_types = HashMap::new();
        let mut global_struct_field_ptrs = HashSet::new();
        let mut global_union_vars = HashSet::new();
        self.collect_top_level_declarations(
            node,
            source,
            &mut global_var_types,
            &mut global_struct_field_ptrs,
            &mut global_union_vars,
        );

        // Each function gets its own scope: a local variable/union declared
        // inside one function is a *different* object than a same-named
        // local declared inside another function, so per-function state
        // (var_types, struct_field_ptrs, union_vars, and critically
        // union_member_accesses) must never be shared across functions.
        // Mirrors the per-function reset pattern used by FIO42-C's
        // FileResourceTracker.
        let functions = query::find_descendants_of_kind(*node, "function_definition");

        if functions.is_empty() {
            // No functions at all (e.g. a header-only or declarations-only
            // snippet) - fall back to treating the whole translation unit as
            // a single scope, matching pre-fix behavior for this edge case.
            self.check_scope(
                node,
                source,
                &global_var_types,
                &global_struct_field_ptrs,
                &global_union_vars,
                &mut violations,
            );
        } else {
            for func in functions {
                let mut var_types = global_var_types.clone();
                let mut struct_field_ptrs = global_struct_field_ptrs.clone();
                let mut union_vars = global_union_vars.clone();
                self.collect_var_types(
                    &func,
                    source,
                    &mut var_types,
                    &mut struct_field_ptrs,
                    &mut union_vars,
                );

                self.check_scope(
                    &func,
                    source,
                    &var_types,
                    &struct_field_ptrs,
                    &union_vars,
                    &mut violations,
                );
            }
        }

        violations
    }
}

impl Exp39C {
    /// Collect variable/union declarations that are direct children of the
    /// translation unit (i.e. file scope, not inside any function body).
    /// These are shared across every function, unlike function-local
    /// declarations which must stay scoped per-function (see `check`).
    fn collect_top_level_declarations(
        &self,
        node: &Node,
        source: &str,
        var_types: &mut HashMap<String, VarTypeInfo>,
        struct_field_ptrs: &mut HashSet<String>,
        union_vars: &mut HashSet<String>,
    ) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "declaration" {
                    self.process_declaration(&child, source, var_types);
                    self.check_union_declaration(&child, source, union_vars);
                    for j in 0..child.child_count() {
                        if let Some(grandchild) = child.child(j) {
                            if grandchild.kind() == "init_declarator" {
                                self.check_struct_field_ptr_init(
                                    &grandchild,
                                    source,
                                    struct_field_ptrs,
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// Run the field-expression / cast / realloc checks over a single scope
    /// (either one function's body or, as a fallback, the whole
    /// translation unit when there are no functions) and immediately run
    /// the union type-punning post-pass against a union_member_accesses map
    /// that is fresh to this scope. Keeping the tracking map scope-local is
    /// what prevents two different functions' same-named union locals from
    /// being aggregated into a single (spurious) type-punning finding.
    fn check_scope(
        &self,
        scope_node: &Node,
        source: &str,
        var_types: &HashMap<String, VarTypeInfo>,
        struct_field_ptrs: &HashSet<String>,
        union_vars: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let mut union_member_accesses: HashMap<String, Vec<(String, usize, usize, bool)>> =
            HashMap::new();
        self.check_node(
            scope_node,
            source,
            violations,
            var_types,
            struct_field_ptrs,
            union_vars,
            &mut union_member_accesses,
        );
        self.check_union_type_punning(union_vars, &union_member_accesses, violations);
    }

    /// Collect variable type information from declarations
    fn collect_var_types(
        &self,
        node: &Node,
        source: &str,
        var_types: &mut HashMap<String, VarTypeInfo>,
        struct_field_ptrs: &mut HashSet<String>,
        union_vars: &mut HashSet<String>,
    ) {
        // Function parameters are declared types too (e.g. `const void
        // *srcPtr`), but they live in a `parameter_declaration` inside the
        // function's `function_declarator`, not in a `declaration` node
        // scanned below. Without this, any cast of an unmatched parameter
        // identifier fell through to `infer_type_from_name`'s naming-based
        // guess and could silently default to "int" (task 569).
        self.collect_parameter_types(node, source, var_types);

        for descendant in query::find_descendants_of_kinds(
            *node,
            &["declaration", "assignment_expression", "init_declarator"],
        ) {
            match descendant.kind() {
                "declaration" => {
                    self.process_declaration(&descendant, source, var_types);
                    self.check_union_declaration(&descendant, source, union_vars);
                }
                // Track struct field pointer assignments: ptr = &struct.field
                "assignment_expression" => {
                    self.check_struct_field_ptr_assignment(&descendant, source, struct_field_ptrs);
                }
                // Track struct field pointer initializations: type *ptr = &struct.field
                "init_declarator" => {
                    self.check_struct_field_ptr_init(&descendant, source, struct_field_ptrs);
                }
                _ => {}
            }
        }
    }

    /// Collect declared types for a function's parameters (e.g. `void
    /// f(const void *srcPtr, unsigned short *dst)`), so casts of a
    /// parameter identifier resolve to its real declared type instead of
    /// falling through to the naming-based `infer_type_from_name` heuristic.
    fn collect_parameter_types(
        &self,
        func_node: &Node,
        source: &str,
        var_types: &mut HashMap<String, VarTypeInfo>,
    ) {
        for declarator in query::find_descendants_of_kind(*func_node, "function_declarator") {
            let Some(params) = declarator.child_by_field_name("parameters") else {
                continue;
            };
            for i in 0..params.child_count() {
                let Some(param) = params.child(i) else {
                    continue;
                };
                if param.kind() != "parameter_declaration" {
                    continue;
                }

                // Base type: same shape as a `declaration` node - the type
                // specifier is a direct child, not a named field.
                let mut base_type = String::new();
                for j in 0..param.child_count() {
                    if let Some(child) = param.child(j) {
                        match child.kind() {
                            "primitive_type" | "sized_type_specifier" | "type_identifier" => {
                                base_type = get_node_text(&child, source).trim().to_string();
                                break;
                            }
                            "struct_specifier" => {
                                base_type = get_node_text(&child, source).trim().to_string();
                                break;
                            }
                            _ => {}
                        }
                    }
                }
                if base_type.is_empty() {
                    continue;
                }

                let Some(name) = self.find_var_name(&param, source) else {
                    continue;
                };

                let declarator_node = param.child_by_field_name("declarator");
                let is_array = declarator_node
                    .map(|d| {
                        d.kind() == "array_declarator" || get_node_text(&d, source).contains('[')
                    })
                    .unwrap_or(false);
                let array_dimensions = declarator_node
                    .map(|d| self.extract_array_dimensions(&d, source))
                    .unwrap_or_default();

                // Do not clobber a more specific local shadow already
                // collected for this scope (parameters are visited first,
                // so this only matters if a caller ever reorders).
                var_types.entry(name).or_insert(VarTypeInfo {
                    base_type,
                    is_array,
                    array_dimensions,
                });
            }
        }
    }

    /// Process a declaration to extract variable types
    fn process_declaration(
        &self,
        node: &Node,
        source: &str,
        var_types: &mut HashMap<String, VarTypeInfo>,
    ) {
        // Get the type specifier
        let mut base_type = String::new();
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "primitive_type" | "sized_type_specifier" | "type_identifier" => {
                        base_type = get_node_text(&child, source).trim().to_string();
                        break;
                    }
                    "struct_specifier" => {
                        // Handle struct declarations like "struct gadget *gp;"
                        base_type = get_node_text(&child, source).trim().to_string();
                        break;
                    }
                    _ => {}
                }
            }
        }

        if base_type.is_empty() {
            return;
        }

        // Get the declarator(s) - handle pointer_declarator for struct pointers
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "init_declarator" | "array_declarator" => {
                        self.extract_var_from_declarator(&child, source, &base_type, var_types);
                    }
                    "pointer_declarator" => {
                        // Handle "struct gadget *gp;"
                        if let Some(var_name) = self.find_var_name(&child, source) {
                            var_types.insert(
                                var_name,
                                VarTypeInfo {
                                    base_type: base_type.clone(),
                                    is_array: false,
                                    array_dimensions: Vec::new(),
                                },
                            );
                        }
                    }
                    "identifier" => {
                        let var_name = get_node_text(&child, source).trim().to_string();
                        var_types.insert(
                            var_name,
                            VarTypeInfo {
                                base_type: base_type.clone(),
                                is_array: false,
                                array_dimensions: Vec::new(),
                            },
                        );
                    }
                    _ => {}
                }
            }
        }
    }

    /// Extract variable name and type from a declarator
    fn extract_var_from_declarator(
        &self,
        node: &Node,
        source: &str,
        base_type: &str,
        var_types: &mut HashMap<String, VarTypeInfo>,
    ) {
        let node_text = get_node_text(node, source);
        let is_array = node.kind() == "array_declarator" || node_text.contains('[');

        // Extract array dimensions
        let array_dimensions = self.extract_array_dimensions(node, source);

        // Find the identifier
        if let Some(var_name) = self.find_var_name(node, source) {
            var_types.insert(
                var_name,
                VarTypeInfo {
                    base_type: base_type.to_string(),
                    is_array,
                    array_dimensions,
                },
            );
        }
    }

    /// Extract array dimensions from a declarator (e.g., [ROWS][COLS])
    /// Returns dimensions in declaration order: for int a[ROWS][COLS], returns ["ROWS", "COLS"]
    fn extract_array_dimensions(&self, node: &Node, source: &str) -> Vec<String> {
        let mut dimensions = Vec::new();
        self.collect_array_dimensions_recursive(node, source, &mut dimensions);
        // Tree-sitter parses array declarators from outer to inner in the AST,
        // but we want them in source order (first dimension first).
        // Since we push as we recurse, the vector is in reverse source order.
        // Reverse it to get proper source order: [ROWS][COLS] -> ["ROWS", "COLS"]
        dimensions.reverse();
        dimensions
    }

    /// Recursively collect array dimensions
    fn collect_array_dimensions_recursive(
        &self,
        node: &Node,
        source: &str,
        dimensions: &mut Vec<String>,
    ) {
        if node.kind() == "array_declarator" {
            // Get the size expression (last child that's not '[' or ']')
            if let Some(size_node) = node.child_by_field_name("size") {
                let size_text = get_node_text(&size_node, source).trim().to_string();
                dimensions.push(size_text);
            }
            // Recurse into nested array declarators
            if let Some(declarator) = node.child_by_field_name("declarator") {
                self.collect_array_dimensions_recursive(&declarator, source, dimensions);
            }
        }

        // Check children for nested array declarators
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "array_declarator" {
                    self.collect_array_dimensions_recursive(&child, source, dimensions);
                }
            }
        }
    }

    /// Find variable name in a declarator
    fn find_var_name(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source).trim().to_string());
        }

        // Check named fields
        if let Some(declarator) = node.child_by_field_name("declarator") {
            return self.find_var_name(&declarator, source);
        }

        // Recurse into children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(name) = self.find_var_name(&child, source) {
                    return Some(name);
                }
            }
        }

        None
    }

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        var_types: &HashMap<String, VarTypeInfo>,
        struct_field_ptrs: &HashSet<String>,
        union_vars: &HashSet<String>,
        union_member_accesses: &mut HashMap<String, Vec<(String, usize, usize, bool)>>,
    ) {
        for descendant in query::find_descendants_of_kinds(
            *node,
            &[
                "cast_expression",
                "assignment_expression",
                "init_declarator",
                "field_expression",
            ],
        ) {
            match descendant.kind() {
                // Look for cast_expression nodes
                "cast_expression" => {
                    self.check_cast_expression(&descendant, source, violations, var_types);
                    self.check_struct_field_ptr_arithmetic(
                        &descendant,
                        source,
                        struct_field_ptrs,
                        violations,
                    );
                }
                // Check for realloc with struct type casting
                "assignment_expression" => {
                    self.check_realloc_cast(&descendant, source, violations, var_types);
                }
                // Also check pointer_declarator assignments with incompatible array types
                "init_declarator" => {
                    self.check_init_declarator(&descendant, source, violations, var_types);
                }
                // Track union member accesses for CWE-188 type punning detection
                "field_expression" => {
                    self.track_union_member_access(
                        &descendant,
                        source,
                        union_vars,
                        union_member_accesses,
                    );
                }
                _ => {}
            }
        }
    }

    /// Check for realloc casts from one struct type to another
    fn check_realloc_cast(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        var_types: &HashMap<String, VarTypeInfo>,
    ) {
        if let Some(right) = node.child_by_field_name("right") {
            // Check if right side is a cast expression containing realloc
            if right.kind() == "cast_expression" {
                let right_text = get_node_text(&right, source);
                if right_text.contains("realloc") {
                    // Get the cast target type
                    if let Some(type_node) = right.child_by_field_name("type") {
                        let target_type = get_node_text(&type_node, source).trim().to_string();

                        // Check if casting to a struct pointer
                        if target_type.contains("struct") && target_type.contains('*') {
                            // Get the variable being assigned to
                            if let Some(left) = node.child_by_field_name("left") {
                                let var_name = get_node_text(&left, source).trim().to_string();

                                // Check if there's a memset after this realloc in the same source
                                // If memset is used to reinitialize, it's compliant
                                let node_end = node.end_byte();
                                let source_after = &source[node_end..];
                                let has_memset = source_after
                                    .contains(&format!("memset({}", var_name))
                                    || source_after.contains(&format!("memset( {}", var_name));

                                if !has_memset {
                                    // Also check the realloc argument type
                                    if let Some(value) = right.child_by_field_name("value") {
                                        self.check_realloc_argument_type(
                                            &value,
                                            source,
                                            &target_type,
                                            var_types,
                                            violations,
                                            node,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check if realloc is called with mismatched pointer type
    fn check_realloc_argument_type(
        &self,
        node: &Node,
        source: &str,
        target_type: &str,
        var_types: &HashMap<String, VarTypeInfo>,
        violations: &mut Vec<RuleViolation>,
        violation_node: &Node,
    ) {
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                let func_name = get_node_text(&func, source).trim();
                if func_name == "realloc" {
                    // Get first argument (the pointer being reallocated)
                    if let Some(args) = node.child_by_field_name("arguments") {
                        for i in 0..args.child_count() {
                            if let Some(arg) = args.child(i) {
                                if arg.kind() != "(" && arg.kind() != ")" && arg.kind() != "," {
                                    let arg_name = get_node_text(&arg, source).trim().to_string();
                                    if let Some(arg_type) = var_types.get(&arg_name) {
                                        // Check if source and target struct types differ
                                        if arg_type.base_type.contains("struct")
                                            && target_type.contains("struct")
                                        {
                                            let target_struct =
                                                self.extract_struct_name(target_type);
                                            let source_struct =
                                                self.extract_struct_name(&arg_type.base_type);

                                            if target_struct != source_struct {
                                                self.report_struct_cast_violation(
                                                    violation_node,
                                                    source,
                                                    &target_struct,
                                                    &source_struct,
                                                    violations,
                                                );
                                            }
                                        }
                                    }
                                    break; // Only check first argument
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Extract struct name from a type string
    fn extract_struct_name(&self, type_str: &str) -> String {
        // Extract "widget" from "struct widget *" or "struct widget"
        let cleaned = type_str
            .replace('*', "")
            .replace("struct", "")
            .trim()
            .to_string();
        cleaned
    }

    /// Report violation for casting between different struct types
    fn report_struct_cast_violation(
        &self,
        node: &Node,
        source: &str,
        target_struct: &str,
        source_struct: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let start_point = node.start_position();
        let stmt_text = get_node_text(node, source).trim().to_string();

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::Medium,
            message: format!(
                "Accessing memory allocated as 'struct {}' through pointer to incompatible 'struct {}': {}",
                source_struct,
                target_struct,
                if stmt_text.len() > 50 {
                    format!("{}...", &stmt_text[..50])
                } else {
                    stmt_text
                }
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(
                "When using realloc to resize memory, ensure the data is properly reinitialized for the new type. Do not access struct members as if they contain valid data from a different struct type.".to_string()
            ),
            ..Default::default()
        });
    }

    fn check_cast_expression(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        var_types: &HashMap<String, VarTypeInfo>,
    ) {
        // Get the type being cast to
        if let Some(type_node) = node.child_by_field_name("type") {
            let target_type = get_node_text(&type_node, source).trim().to_string();

            // Get the value being cast
            if let Some(value_node) = node.child_by_field_name("value") {
                // Check if this is a pointer cast
                if target_type.contains('*') {
                    // Extract base types
                    let target_base = self.extract_base_type(&target_type);
                    let source_base = self.infer_source_type(&value_node, source, var_types);

                    if let (Some(target), Some(source_type)) = (target_base, source_base) {
                        if self.are_incompatible_pointer_types(&target, &source_type) {
                            self.report_incompatible_cast_violation(
                                node,
                                source,
                                &target,
                                &source_type,
                                violations,
                            );
                        }
                    }
                }
            }
        }
    }

    fn check_init_declarator(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        var_types: &HashMap<String, VarTypeInfo>,
    ) {
        // Check for array pointer type mismatches like: int (*b)[ROWS] = a;
        if let Some(declarator) = node.child_by_field_name("declarator") {
            if let Some(value) = node.child_by_field_name("value") {
                let declarator_text = get_node_text(&declarator, source);
                let value_text = get_node_text(&value, source).trim().to_string();

                // Check for pointer to array declarations: (*var)[size]
                if declarator_text.contains("(*") && declarator_text.contains('[') {
                    // Extract the dimension from the pointer-to-array declaration
                    // e.g., (*b)[ROWS] should extract "ROWS"
                    if let Some(ptr_dimension) =
                        self.extract_pointer_array_dimension(&declarator_text)
                    {
                        // Check if value is an array variable
                        if let Some(var_info) = var_types.get(&value_text) {
                            if var_info.is_array && !var_info.array_dimensions.is_empty() {
                                // For int a[ROWS][COLS], the second dimension should match
                                // int (*b)[COLS] = a; is valid (pointer to array of COLS ints)
                                // int (*b)[ROWS] = a; is invalid (wrong dimension)

                                // The pointer-to-array dimension should match the LAST dimension
                                // of the source array (the inner-most array dimension)
                                let last_dimension = var_info.array_dimensions.last();
                                if let Some(last_dim) = last_dimension {
                                    if *last_dim != ptr_dimension {
                                        self.report_array_dimension_violation(
                                            node, source, violations,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Extract the dimension from a pointer-to-array declaration like "(*b)[ROWS]"
    fn extract_pointer_array_dimension(&self, decl_text: &str) -> Option<String> {
        // Find the last [...] in the declarator
        if let Some(bracket_start) = decl_text.rfind('[') {
            if let Some(bracket_end) = decl_text.rfind(']') {
                if bracket_start < bracket_end {
                    let dimension = decl_text[bracket_start + 1..bracket_end].trim().to_string();
                    if !dimension.is_empty() {
                        return Some(dimension);
                    }
                }
            }
        }
        None
    }

    fn extract_base_type(&self, type_str: &str) -> Option<String> {
        // Remove pointer asterisks, const, volatile, etc.
        let cleaned = type_str
            .replace("const", "")
            .replace("volatile", "")
            .replace("restrict", "")
            .replace('*', "")
            .replace(['(', ')'], "")
            .trim()
            .to_string();

        if cleaned.is_empty() {
            None
        } else {
            Some(cleaned)
        }
    }

    fn infer_source_type(
        &self,
        node: &Node,
        source: &str,
        var_types: &HashMap<String, VarTypeInfo>,
    ) -> Option<String> {
        // Try to infer the type from the expression
        match node.kind() {
            "pointer_expression" => {
                // Address-of operator: &variable
                if let Some(argument) = node.child_by_field_name("argument") {
                    let arg_text = get_node_text(&argument, source).trim().to_string();
                    // Check if we have type info for this variable
                    if let Some(var_info) = var_types.get(&arg_text) {
                        return Some(var_info.base_type.clone());
                    }
                    // This is simplified - in reality we'd need type information
                    // For now, check common patterns
                    if arg_text.contains("float") {
                        return Some("float".to_string());
                    } else if arg_text.contains("double") {
                        return Some("double".to_string());
                    }
                    // Try to infer from the variable name (heuristic)
                    return self.infer_type_from_name(&arg_text);
                }
            }
            "identifier" => {
                let name = get_node_text(node, source).trim().to_string();
                // Check if we have type info for this variable
                if let Some(var_info) = var_types.get(&name) {
                    return Some(var_info.base_type.clone());
                }
                return self.infer_type_from_name(&name);
            }
            "cast_expression" => {
                // Nested cast - get the target type of the inner cast
                if let Some(type_node) = node.child_by_field_name("type") {
                    let inner_type = get_node_text(&type_node, source).trim().to_string();
                    return self.extract_base_type(&inner_type);
                }
            }
            _ => {}
        }
        None
    }

    fn infer_type_from_name(&self, name: &str) -> Option<String> {
        // Heuristic: try to infer type from variable naming conventions.
        // This only runs once `var_types` (which now includes function
        // parameters, see `collect_parameter_types`) has already failed to
        // resolve the identifier. Falling back to a concrete guess (e.g.
        // defaulting unmatched names to "int") fabricates a type the source
        // never declared and manufactures false-confidence violations
        // (task 569: raylib's `GetPixelColor` parameter went unmatched and
        // was silently treated as `int`, producing 31/31 FPs). When no
        // naming convention matches, return `None` (unknown type) so the
        // caller treats the cast as unanalyzable rather than firing on a
        // fabricated type.
        let lower_name = name.to_lowercase();

        if lower_name.starts_with('f') || lower_name.contains("float") {
            Some("float".to_string())
        } else if lower_name.starts_with("db") || lower_name.contains("double") {
            Some("double".to_string())
        } else if lower_name.starts_with("ch") || lower_name.contains("char") {
            Some("char".to_string())
        } else if lower_name.starts_with("sh") || lower_name.contains("short") {
            Some("short".to_string())
        } else if lower_name.starts_with('l') && lower_name.contains("long") {
            Some("long".to_string())
        } else {
            None
        }
    }

    fn are_incompatible_pointer_types(&self, target_type: &str, source_type: &str) -> bool {
        // Check if the two pointer types are incompatible

        // Same types are compatible
        if target_type == source_type {
            return false;
        }

        // Character types can alias anything (exception in strict aliasing rules)
        if target_type == "char" || target_type == "unsigned char" || target_type == "signed char" {
            return false;
        }
        if source_type == "char" || source_type == "unsigned char" || source_type == "signed char" {
            return false;
        }

        // void* is compatible with any pointer type
        if target_type == "void" || source_type == "void" {
            return false;
        }

        // Signed/unsigned variants of the same type are compatible
        let target_normalized = target_type.replace("unsigned ", "").replace("signed ", "");
        let source_normalized = source_type.replace("unsigned ", "").replace("signed ", "");
        if target_normalized == source_normalized {
            return false;
        }

        // Different integer types with different sizes are incompatible
        // This catches short* -> int*, int* -> short*, etc.
        let incompatible_pairs = [
            ("float", "int"),
            ("int", "float"),
            ("double", "int"),
            ("int", "double"),
            ("float", "short"),
            ("short", "float"),
            ("double", "long"),
            ("long", "double"),
            ("float", "long"),
            ("long", "float"),
            ("short", "int"),
            ("int", "short"),
            ("short", "long"),
            ("long", "short"),
        ];

        for (type1, type2) in &incompatible_pairs {
            if (target_type.contains(type1) && source_type.contains(type2))
                || (target_type.contains(type2) && source_type.contains(type1))
            {
                return true;
            }
        }

        false
    }

    #[allow(dead_code)]
    fn has_array_dimension_mismatch(&self, declarator: &str, _value: &str) -> bool {
        // Simplified check for array dimension mismatches
        // This would need more sophisticated parsing in a complete implementation
        declarator.contains("(*") && declarator.contains("][")
    }

    fn report_incompatible_cast_violation(
        &self,
        node: &Node,
        source: &str,
        target_type: &str,
        source_type: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let start_point = node.start_position();
        let cast_text = get_node_text(node, source).trim().to_string();

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::Medium,
            message: format!(
                "Do not access a '{}' object through a pointer of incompatible type '{}*': {}",
                source_type,
                target_type,
                if cast_text.len() > 50 {
                    format!("{}...", &cast_text[..50])
                } else {
                    cast_text
                }
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(
                "Avoid casting between incompatible pointer types. Use type-appropriate operations or unions for legitimate type punning. Consider using standard library functions instead of direct type manipulation.".to_string()
            ),
            ..Default::default()
        });
    }

    fn report_array_dimension_violation(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let start_point = node.start_position();
        let decl_text = get_node_text(node, source).trim().to_string();

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::Medium,
            message: format!(
                "Array pointer dimension mismatch detected: {}",
                if decl_text.len() > 60 {
                    format!("{}...", &decl_text[..60])
                } else {
                    decl_text
                }
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(
                "Ensure array pointer dimensions match the array being assigned. Incompatible array types can lead to undefined behavior.".to_string()
            ),
            ..Default::default()
        });
    }

    // ── CWE-188: Struct memory layout assumption detection ──────────────────

    /// Check if a declaration is a union type and track the variable name
    fn check_union_declaration(&self, node: &Node, source: &str, union_vars: &mut HashSet<String>) {
        let mut has_union = false;
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "union_specifier" {
                    has_union = true;
                    break;
                }
            }
        }
        if !has_union {
            return;
        }
        // Extract variable name from direct children (not from union body)
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "identifier" => {
                        let name = get_node_text(&child, source).trim().to_string();
                        union_vars.insert(name);
                    }
                    "init_declarator" | "pointer_declarator" => {
                        if let Some(name) = self.find_var_name(&child, source) {
                            union_vars.insert(name);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Check if an assignment stores &struct.field into a variable
    fn check_struct_field_ptr_assignment(
        &self,
        node: &Node,
        source: &str,
        struct_field_ptrs: &mut HashSet<String>,
    ) {
        if let Some(left) = node.child_by_field_name("left") {
            if left.kind() == "identifier" {
                if let Some(right) = node.child_by_field_name("right") {
                    if self.is_address_of_struct_field(&right, source) {
                        let var_name = get_node_text(&left, source).trim().to_string();
                        struct_field_ptrs.insert(var_name);
                    }
                }
            }
        }
    }

    /// Check if an init_declarator initializes with &struct.field
    fn check_struct_field_ptr_init(
        &self,
        node: &Node,
        source: &str,
        struct_field_ptrs: &mut HashSet<String>,
    ) {
        if let Some(value) = node.child_by_field_name("value") {
            if self.is_address_of_struct_field(&value, source) {
                if let Some(var_name) = self.find_var_name(node, source) {
                    struct_field_ptrs.insert(var_name);
                }
            }
        }
    }

    /// Check if a node is &struct_var.field (address-of a struct field)
    fn is_address_of_struct_field(&self, node: &Node, source: &str) -> bool {
        if node.kind() != "pointer_expression" {
            return false;
        }
        let text = get_node_text(node, source).trim();
        if !text.starts_with('&') {
            return false;
        }
        if let Some(arg) = node.child_by_field_name("argument") {
            return arg.kind() == "field_expression";
        }
        false
    }

    /// Detect cast expressions involving struct field pointer arithmetic (CWE-188 modify_local)
    /// Pattern: *(int*)(charPtr + sizeof(int)) where charPtr = &struct.field
    fn check_struct_field_ptr_arithmetic(
        &self,
        cast_node: &Node,
        source: &str,
        struct_field_ptrs: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if struct_field_ptrs.is_empty() {
            return;
        }
        // Must be a pointer cast
        if let Some(type_node) = cast_node.child_by_field_name("type") {
            let target_type = get_node_text(&type_node, source);
            if !target_type.contains('*') {
                return;
            }
        } else {
            return;
        }
        // Check if value involves pointer arithmetic with a struct field pointer
        if let Some(value) = cast_node.child_by_field_name("value") {
            if self.contains_struct_field_ptr_arithmetic(&value, source, struct_field_ptrs) {
                let start = cast_node.start_position();
                let text = get_node_text(cast_node, source).trim().to_string();
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "Pointer arithmetic on struct field address with type cast assumes specific memory layout: {}",
                        if text.len() > 60 { format!("{}...", &text[..60]) } else { text }
                    ),
                    file_path: String::new(),
                    line: start.row + 1,
                    column: start.column + 1,
                    suggestion: Some(
                        "Access struct fields by name instead of using pointer arithmetic with assumed offsets. Struct layout may include padding.".to_string()
                    ),
                    ..Default::default()
                });
            }
        }
    }

    /// Check if an expression contains pointer arithmetic with a struct field pointer
    fn contains_struct_field_ptr_arithmetic(
        &self,
        node: &Node,
        source: &str,
        struct_field_ptrs: &HashSet<String>,
    ) -> bool {
        match node.kind() {
            "binary_expression" => {
                // Check if either operand is a struct field pointer
                for field in &["left", "right"] {
                    if let Some(operand) = node.child_by_field_name(field) {
                        if operand.kind() == "identifier" {
                            let name = get_node_text(&operand, source).trim().to_string();
                            if struct_field_ptrs.contains(&name) {
                                return true;
                            }
                        }
                    }
                }
                false
            }
            "parenthesized_expression" => {
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() != "(" && child.kind() != ")" {
                            return self.contains_struct_field_ptr_arithmetic(
                                &child,
                                source,
                                struct_field_ptrs,
                            );
                        }
                    }
                }
                false
            }
            _ => false,
        }
    }

    /// Track union member accesses for type punning detection
    fn track_union_member_access(
        &self,
        node: &Node,
        source: &str,
        union_vars: &HashSet<String>,
        union_member_accesses: &mut HashMap<String, Vec<(String, usize, usize, bool)>>,
    ) {
        if union_vars.is_empty() {
            return;
        }
        // Only process outermost field_expression in a chain
        // Skip if parent is also a field_expression and we're its argument
        if let Some(parent) = node.parent() {
            if parent.kind() == "field_expression" {
                if let Some(parent_arg) = parent.child_by_field_name("argument") {
                    if parent_arg.id() == node.id() {
                        return;
                    }
                }
            }
        }

        // Check if this is a "deep" access (u.struct_member.field — 3+ levels)
        // This indicates sub-field access into a struct union member, which is
        // layout-dependent (byte-order, alignment)
        let is_deep = node
            .child_by_field_name("argument")
            .map(|arg| arg.kind() == "field_expression")
            .unwrap_or(false);

        let (root, member) = self.get_field_access_root_and_member(node, source);
        if let (Some(root_name), Some(member_name)) = (root, member) {
            if union_vars.contains(&root_name) {
                union_member_accesses.entry(root_name).or_default().push((
                    member_name,
                    node.start_position().row + 1,
                    node.start_position().column + 1,
                    is_deep,
                ));
            }
        }
    }

    /// Walk a field_expression chain to find root variable and first member name
    /// For u.a → (u, a); for u.a.b.c → (u, a)
    fn get_field_access_root_and_member(
        &self,
        node: &Node,
        source: &str,
    ) -> (Option<String>, Option<String>) {
        let mut current = *node;
        loop {
            if current.kind() != "field_expression" {
                break;
            }
            if let Some(arg) = current.child_by_field_name("argument") {
                if arg.kind() == "field_expression" {
                    current = arg;
                } else {
                    // arg is the root (identifier)
                    let root = get_node_text(&arg, source).trim().to_string();
                    let member = current
                        .child_by_field_name("field")
                        .map(|f| get_node_text(&f, source).trim().to_string());
                    return (Some(root), member);
                }
            } else {
                break;
            }
        }
        (None, None)
    }

    /// Post-pass: flag union variables with layout-dependent type punning
    /// Only flags when: (1) multiple different members accessed AND (2) at least one
    /// access is "deep" (u.struct_member.field), indicating byte-order/alignment dependency
    fn check_union_type_punning(
        &self,
        union_vars: &HashSet<String>,
        union_member_accesses: &HashMap<String, Vec<(String, usize, usize, bool)>>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for (var_name, accesses) in union_member_accesses {
            if !union_vars.contains(var_name) {
                continue;
            }
            let unique_members: HashSet<&str> =
                accesses.iter().map(|(m, _, _, _)| m.as_str()).collect();
            if unique_members.len() < 2 {
                continue;
            }
            let has_deep = accesses.iter().any(|(_, _, _, deep)| *deep);
            if !has_deep {
                continue;
            }
            // Flag the deep accesses (sub-field access into struct union member)
            let mut seen_members: HashSet<&str> = HashSet::new();
            let mut first_member: Option<&str> = None;
            for (member, line, col, is_deep) in accesses {
                if first_member.is_none() {
                    first_member = Some(member);
                    seen_members.insert(member);
                } else if let Some(first) = first_member {
                    if !seen_members.contains(member.as_str()) && *is_deep {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Medium,
                            message: format!(
                                "Accessing union '{}' member '{}' after writing to '{}' relies on data memory layout (byte-order, alignment, packing)",
                                var_name, member, first
                            ),
                        file_path: String::new(),
                        line: *line,
                        column: *col,
                        suggestion: Some(
                            "Avoid relying on byte-order or alignment of union fields. Use type-appropriate bitwise operations instead of union type punning.".to_string()
                        ),
                            ..Default::default()
                        });
                        seen_members.insert(member);
                    }
                }
            }
        }
    }
}
