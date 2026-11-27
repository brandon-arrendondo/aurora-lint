// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::{ProjectContext, VisibleTypes};
use crate::manifest::Severity;
use crate::settings::{AnalysisSettings, IntFacts};
use crate::utility::cert_c::ast_utils::{self, get_identifier_from_declarator};
use crate::utility::cert_c::declarator_utils::{is_array_declarator, is_pointer_declarator};
use crate::utility::cert_c::expr_type::{self, CType, Rank, TypeEnv};
use crate::utility::cert_c::overflow_helpers;
use crate::utility::cert_c::pointer_typing::{self, PointerFacts};
use lang_parsing_substrate::query;
use std::cell::{Cell, OnceCell, RefCell};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

/// What the project and the file's headers say about types, for reading
/// whether an operand is a pointer.
#[derive(Default)]
pub struct Arr39C {
    /// The types the file sees: its headers' typedefs, struct members and
    /// member declarator shapes.
    visible: RefCell<VisibleTypes>,
    /// `ProjectContext::project_array_objects`: file-scope arrays a header
    /// declares.
    project_arrays: RefCell<Arc<HashSet<String>>>,
    /// `ProjectContext::project_pointer_objects`: file-scope pointers a
    /// header or another file declares, with their type spelling.
    project_pointers: RefCell<Arc<HashMap<String, String>>>,
    /// `ProjectContext::pointer_typedef_names`, for a pointer typedef only a
    /// header defines.
    pointer_typedefs: RefCell<Arc<HashSet<String>>>,
    /// `ProjectContext::function_pointer_typedef_names`, likewise.
    function_pointer_typedefs: RefCell<Arc<HashSet<String>>>,
    /// The settings' data model.
    data_model: Cell<IntFacts>,
}

impl CertRule for Arr39C {
    fn rule_id(&self) -> &'static str {
        "ARR39-C"
    }

    fn description(&self) -> &'static str {
        "Do not add or subtract a scaled integer to a pointer"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "ARR39-C"
    }

    fn reads_header_facts(&self) -> bool {
        true
    }

    fn set_analysis_settings(&self, settings: &Arc<AnalysisSettings>) {
        self.data_model.set(settings.facts);
    }

    fn set_project_context(&self, context: &ProjectContext) {
        self.visible.borrow_mut().struct_field_types = context.struct_field_types.clone();
        *self.project_arrays.borrow_mut() = Arc::new(context.project_array_objects());
        *self.project_pointers.borrow_mut() = Arc::new(context.project_pointer_objects());
        *self.pointer_typedefs.borrow_mut() = context.pointer_typedef_names.clone();
        *self.function_pointer_typedefs.borrow_mut() =
            context.function_pointer_typedef_names.clone();
    }

    fn set_visible_types(&self, types: &VisibleTypes) {
        *self.visible.borrow_mut() = types.clone();
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let visible = self.visible.borrow().clone();
        let pointer_typedefs = self.pointer_typedefs.borrow().clone();
        let function_pointer_typedefs = self.function_pointer_typedefs.borrow().clone();
        let typedefs = OnceCell::new();
        let types = OperandTypes {
            root: ast_utils::tree_root(node),
            source,
            visible: &visible,
            project_arrays: self.project_arrays.borrow().clone(),
            project_pointers: self.project_pointers.borrow().clone(),
            pointer_typedefs: &pointer_typedefs,
            function_pointer_typedefs: &function_pointer_typedefs,
            model: self.data_model.get(),
            typedefs: &typedefs,
            facts: OnceCell::new(),
            env: OnceCell::new(),
            macros: OnceCell::new(),
            variable_types: RefCell::new(HashMap::new()),
        };
        self.check_node(node, source, &types, violations);
    }
}

/// What one file types an operand against, each part built on the first
/// operand that needs it.
struct OperandTypes<'a> {
    root: Node<'a>,
    source: &'a str,
    visible: &'a VisibleTypes,
    project_arrays: Arc<HashSet<String>>,
    project_pointers: Arc<HashMap<String, String>>,
    pointer_typedefs: &'a HashSet<String>,
    function_pointer_typedefs: &'a HashSet<String>,
    model: IntFacts,
    typedefs: &'a OnceCell<HashMap<String, String>>,
    facts: OnceCell<PointerFacts>,
    env: OnceCell<TypeEnv<'a>>,
    /// The file's object-like macros, with the offset of each `#define`.
    macros: OnceCell<HashMap<String, Vec<usize>>>,
    /// Each function's `{name -> declared type}` map, by the function's
    /// node id.
    variable_types: RefCell<HashMap<usize, Arc<HashMap<String, String>>>>,
}

impl<'a> OperandTypes<'a> {
    /// Whether `operand`'s value has pointer or array type by the
    /// declarations it resolves to (ADR-0006): positive only, so an operand
    /// whose type does not resolve is not a pointer and no finding is made
    /// on it. The pointer-typing facts answer first; the expression typer
    /// answers what they leave, such as `*pp + i`, `arr[k]` or a variable
    /// of a pointer typedef. A name an enumerator in scope makes a constant
    /// is none, whatever object outside that scope it would otherwise name.
    fn is_pointer(&self, operand: &Node) -> bool {
        if operand.kind() == "identifier"
            && ast_utils::names_enumerator_in_scope(
                &self.root,
                operand,
                ast_utils::get_node_text(operand, self.source),
                self.source,
            )
        {
            return false;
        }
        let facts = self.facts.get_or_init(|| {
            PointerFacts::collect(&self.root, self.source).with_project(
                self.project_arrays.clone(),
                self.visible.struct_field_shapes.clone(),
            )
        });
        let variable_types = overflow_helpers::enclosing_function_definition(operand)
            .map(|function| {
                self.variable_types
                    .borrow_mut()
                    .entry(function.id())
                    .or_insert_with(|| {
                        Arc::new(overflow_helpers::collect_variable_types(
                            &function,
                            self.source,
                        ))
                    })
                    .clone()
            })
            .unwrap_or_default();
        if pointer_typing::expr_is_pointer(
            operand,
            self.source,
            &variable_types,
            &self.visible.struct_field_types,
            facts,
        ) {
            return true;
        }
        let env = self.env();
        matches!(
            expr_type::expr_type(operand, self.source, env)
                .or_else(|| self.project_object_type(operand)),
            Some(CType::Pointer(_) | CType::Array(_))
        )
    }

    /// The type a project pointer object has when `operand` names one: an
    /// identifier no declaration in this file binds, which some header or
    /// other file declares as a pointer (`extern int *g;`). ADR-0006: a name
    /// the file declares is answered by that declaration only, and one an
    /// enumerator in scope or an object-like `#define` earlier in the file
    /// gives is no object at all. The project table already drops a name a
    /// header makes a file-scope enumerator or an object-like macro.
    fn project_object_type(&self, operand: &Node) -> Option<CType> {
        if operand.kind() != "identifier" {
            return None;
        }
        let name = ast_utils::get_node_text(operand, self.source);
        let spelling = self.project_pointers.get(name)?;
        if ast_utils::resolve_identifier_declarator_in(&self.root, operand, name, self.source)
            .is_some()
            || ast_utils::enumerator_in_scope(operand, name, self.source)
            || self.macro_defined_before(operand, name)
        {
            return None;
        }
        expr_type::classify_spelling(spelling, self.env())
    }

    /// Whether the file defines `name` as an object-like macro before
    /// `operand`, which then replaces it there.
    fn macro_defined_before(&self, operand: &Node, name: &str) -> bool {
        self.macros
            .get_or_init(|| ast_utils::object_like_macro_definitions(self.source))
            .get(name)
            .is_some_and(|at| at.iter().any(|&offset| offset < operand.start_byte()))
    }

    /// Whether `operand` is a pointer to, or an array of, a character type
    /// or an exactly 8-bit integer by its declared type, or a pointer to
    /// `void`, which GNU C moves by bytes: adding a byte count to it is byte
    /// arithmetic, scaled once. A sum or difference the typer
    /// cannot type, because an integer operand's type is not fixed (`p + n *
    /// sizeof(x)` where the data model leaves `size_t`'s rank open), has its
    /// pointer operand's type.
    fn points_to_bytes(&self, operand: &Node) -> bool {
        let typed = expr_type::expr_type(operand, self.source, self.env())
            .or_else(|| self.project_object_type(operand));
        let element = match typed {
            Some(CType::Pointer(Some(element)) | CType::Array(Some(element))) => element,
            None => {
                return match operand.kind() {
                    "parenthesized_expression" => operand
                        .named_child(0)
                        .is_some_and(|inner| self.points_to_bytes(&inner)),
                    "binary_expression" => {
                        let operator = operand
                            .child_by_field_name("operator")
                            .map(|o| ast_utils::get_node_text(&o, self.source));
                        matches!(operator, Some("+" | "-"))
                            && ["left", "right"].iter().any(|side| {
                                operand
                                    .child_by_field_name(side)
                                    .is_some_and(|o| self.points_to_bytes(&o))
                            })
                    }
                    _ => false,
                };
            }
            _ => return false,
        };
        matches!(
            *element,
            CType::Int {
                rank: Rank::Char,
                ..
            } | CType::IntOfWidth {
                max_bits: Some(8),
                ..
            } | CType::Void
        )
    }

    /// The expression typer's environment over the file's visible types and
    /// its pointer typedefs, built on first use.
    fn env(&self) -> &TypeEnv<'a> {
        self.env.get_or_init(|| {
            let typedefs = self.typedefs.get_or_init(|| {
                expr_type::typedefs_with_derivations(
                    &self.visible.typedef_types,
                    &self.root,
                    self.source,
                    self.pointer_typedefs,
                    self.function_pointer_typedefs,
                )
            });
            TypeEnv::new(
                typedefs,
                &self.visible.struct_field_types,
                &self.visible.struct_field_shapes,
                &self.visible.struct_typedef_aliases,
                self.model,
            )
            .under_edition(self.visible.c_standard)
            .in_tree(self.root)
        })
    }
}

impl Arr39C {
    fn check_node(
        &self,
        node: &Node,
        source: &str,
        types: &OperandTypes,
        violations: &mut Vec<RuleViolation>,
    ) {
        let matches = query::find_descendants_of_kinds(
            *node,
            &[
                "binary_expression",
                "assignment_expression",
                "call_expression",
                "while_statement",
                "for_statement",
                "subscript_expression",
            ],
        );

        for matched in matches {
            match matched.kind() {
                "binary_expression" => {
                    self.check_pointer_arithmetic(&matched, source, types, violations);
                }
                "assignment_expression" => {
                    self.check_assignment_arithmetic(&matched, source, types, violations);
                }
                "call_expression" => {
                    self.check_function_call_scaling(&matched, source, violations);
                }
                "while_statement" | "for_statement" => {
                    self.check_loop_pointer_arithmetic(&matched, source, violations);
                }
                "subscript_expression" => {
                    // Check for violations in array subscript like ptr[scaled_value]
                    self.check_subscript_scaling(&matched, source, types, violations);
                }
                _ => {}
            }
        }
    }

    fn check_pointer_arithmetic(
        &self,
        node: &Node,
        source: &str,
        types: &OperandTypes,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(operator) = self.get_operator(node, source) {
            if operator == "+" || operator == "-" {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    // Check if this is pointer + scaled_integer or pointer - scaled_integer
                    if self.is_pointer_scaled_arithmetic(&left, &right, source)
                        && types.is_pointer(&left)
                        && (Self::scaled_by_char_size(&right, source)
                            || !types.points_to_bytes(&left))
                    {
                        let start_point = node.start_position();
                        let expr_text = &source[node.start_byte()..node.end_byte()];

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::High,
                            message: format!(
                                "Scaled integer arithmetic with pointer: '{}'. This results in double scaling",
                                expr_text
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some("Remove sizeof() or use unscaled integer arithmetic".to_string()),
                        ..Default::default()
                        });
                    }
                }
            }
        }
    }

    fn check_assignment_arithmetic(
        &self,
        node: &Node,
        source: &str,
        types: &OperandTypes,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(operator) = self.get_assignment_operator(node, source) {
            if operator == "+=" || operator == "-=" {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    let left_text = &source[left.start_byte()..left.end_byte()];

                    // Check if this is pointer += scaled_integer
                    if self.is_scaled_integer_expression(&right, source)
                        && self.looks_like_pointer(&left, source)
                        && !self.is_char_pointer(&left, source)  // Char pointers are allowed
                        && !left_text.to_lowercase().contains("byte") // Byte pointers are allowed
                        && types.is_pointer(&left)
                        && !types.points_to_bytes(&left)
                    {
                        let start_point = node.start_position();
                        let expr_text = &source[node.start_byte()..node.end_byte()];

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::High,
                            message: format!(
                                "Scaled integer assignment to pointer: '{}'. This results in double scaling",
                                expr_text
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some("Use unscaled integer increment without sizeof()".to_string()),
                        ..Default::default()
                        });
                    }
                }
            }
        }
    }

    fn check_subscript_scaling(
        &self,
        node: &Node,
        source: &str,
        types: &OperandTypes,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check for ptr[sizeof_value] pattern
        if let (Some(argument), Some(index)) = (
            node.child_by_field_name("argument"),
            node.child_by_field_name("index"),
        ) {
            let arg_text = &source[argument.start_byte()..argument.end_byte()];

            // Check if index is a scaled value (from sizeof or byte-related variable)
            if self.is_scaled_integer_expression(&index, source)
                && self.looks_like_pointer_node(&argument, source)
                && !self.is_char_pointer(&argument, source)
                && !arg_text.to_lowercase().contains("byte") // Byte pointers are allowed
                && types.is_pointer(&argument)
                && !types.points_to_bytes(&argument)
            {
                let start_point = node.start_position();
                let expr_text = &source[node.start_byte()..node.end_byte()];

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Array subscript with scaled integer: '{}'. This results in double scaling",
                        expr_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some(
                        "Use unscaled index or element count instead of sizeof()".to_string(),
                    ),
                    ..Default::default()
                });
            }
        }
    }

    fn check_function_call_scaling(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = &source[function_node.start_byte()..function_node.end_byte()];

            // Check specific functions that commonly have scaling issues
            match function_name {
                "fgetws" | "fputws" => {
                    self.check_wide_string_function_scaling(
                        node,
                        source,
                        function_name,
                        violations,
                    );
                }
                "memset" | "memcpy" | "memmove" => {
                    self.check_memory_function_scaling(node, source, function_name, violations);
                }
                _ => {}
            }
        }
    }

    fn check_loop_pointer_arithmetic(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check if loop condition uses sizeof(array) as upper bound
        // Pattern: for (i = 0; i < sizeof(data); i++) { ptr[i] or *(ptr+i) }
        if let Some(condition) = self.find_loop_condition(node) {
            let condition_text = &source[condition.start_byte()..condition.end_byte()];

            // Check if sizeof is used as loop bound
            if condition_text.contains("sizeof(") {
                // Find the loop body
                if let Some(body) = self.find_loop_body(node) {
                    // Check if body uses pointer arithmetic or subscripting
                    if self.has_pointer_operations_in_loop(&body, source) {
                        let start_point = condition.start_position();

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::High,
                            message: "Loop uses sizeof() as bound (byte count) but performs pointer arithmetic (element-based), causing double scaling".to_string(),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some("Use array element count (sizeof(array)/sizeof(array[0])) instead of sizeof(array) in loop bound".to_string()),
                            ..Default::default()
                        });
                        return; // Only report once per loop
                    }
                }
            }
        }

        // Original check: Look for patterns like: while (ptr < (buf + sizeof(buf)))
        let node_text = &source[node.start_byte()..node.end_byte()];

        if node_text.contains("sizeof(") && (node_text.contains(" + ") || node_text.contains(" - "))
        {
            // Look for pointer comparison with sizeof scaling
            if let Some(condition) = self.find_loop_condition(node) {
                if self.has_scaled_pointer_comparison(&condition, source) {
                    let start_point = condition.start_position();

                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: "Loop condition uses scaled pointer arithmetic with sizeof(), causing double scaling".to_string(),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Use array element count instead of sizeof() in pointer arithmetic".to_string()),
                    ..Default::default()
                    });
                }
            }
        }
    }

    fn find_loop_body<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        match node.kind() {
            "for_statement" => node.child_by_field_name("body"),
            "while_statement" => node.child_by_field_name("body"),
            "do_statement" => node.child_by_field_name("body"),
            _ => None,
        }
    }

    fn has_pointer_operations_in_loop(&self, body: &Node, source: &str) -> bool {
        // Check for pointer arithmetic (ptr + i, ptr - i) or subscripting (ptr[i])
        query::find_first_descendant(*body, |node| self.node_is_pointer_op(&node, source)).is_some()
    }

    fn node_is_pointer_op(&self, node: &Node, source: &str) -> bool {
        match node.kind() {
            "subscript_expression" => {
                // Found ptr[i] pattern
                if let Some(argument) = node.child_by_field_name("argument") {
                    // Check if the argument looks like a pointer (not char*)
                    if self.looks_like_pointer_node(&argument, source)
                        && !self.is_char_pointer(&argument, source)
                    {
                        return true;
                    }
                }
            }
            "binary_expression" => {
                // Check for pointer +/- operations
                if let Some(operator_node) = node.child_by_field_name("operator") {
                    let op = &source[operator_node.start_byte()..operator_node.end_byte()];
                    if op == "+" || op == "-" {
                        if let Some(left) = node.child_by_field_name("left") {
                            if self.looks_like_pointer_node(&left, source)
                                && !self.is_char_pointer(&left, source)
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            "pointer_expression" => {
                // Check for *(ptr + i) pattern
                if let Some(argument) = node.child_by_field_name("argument") {
                    if argument.kind() == "binary_expression" {
                        if let Some(operator_node) = argument.child_by_field_name("operator") {
                            let op = &source[operator_node.start_byte()..operator_node.end_byte()];
                            if op == "+" || op == "-" {
                                if let Some(left) = argument.child_by_field_name("left") {
                                    if self.looks_like_pointer_node(&left, source) {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        false
    }

    fn check_wide_string_function_scaling(
        &self,
        node: &Node,
        source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let args = self.get_function_arguments(node, source);

        for (i, arg) in args.iter().enumerate() {
            if arg.contains("wcslen(") && arg.contains("sizeof(wchar_t)") {
                let start_point = node.start_position();
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Function '{}' argument {} uses scaled arithmetic: '{}'. wcslen already returns character count",
                        function_name, i + 1, arg
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Remove '* sizeof(wchar_t)' multiplication".to_string()),
                ..Default::default()
                });
            }
        }
    }

    fn check_memory_function_scaling(
        &self,
        node: &Node,
        source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(arguments) = node.child_by_field_name("arguments") {
            // Look for patterns in the first argument (destination pointer arithmetic)
            for i in 0..arguments.child_count() {
                if let Some(arg) = arguments.child(i) {
                    if arg.kind() != "," {
                        let arg_text = &source[arg.start_byte()..arg.end_byte()];

                        // Check for scaled offset patterns like: struct_ptr + offsetof(...) * sizeof(...)
                        if self.is_scaled_offset_pattern(arg_text) {
                            let start_point = arg.start_position();
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::High,
                                message: format!(
                                    "Function '{}' called with scaled offset. offsetof() result is already scaled",
                                    function_name
                                ),
                                file_path: String::new(),
                                line: start_point.row + 1,
                                column: start_point.column + 1,
                                suggestion: Some("Use char* pointer to avoid scaling or remove extra scaling".to_string()),
                            ..Default::default()
                            });
                        }
                        break; // Only check first argument for destination pointer
                    }
                }
            }
        }
    }

    /// Check if a text is an ALL_CAPS identifier (macro/enum constant)
    fn is_all_caps_identifier(text: &str) -> bool {
        !text.is_empty()
            && text
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    }

    /// Recursively check if an expression consists entirely of ALL_CAPS
    /// identifiers and arithmetic operators (macro/enum constant arithmetic).
    /// Handles nested binary_expressions like `A + B + C` parsed as `(A + B) + C`.
    fn is_all_caps_arithmetic(node: &Node, source: &str) -> bool {
        match node.kind() {
            "identifier" => {
                let text = &source[node.start_byte()..node.end_byte()];
                Self::is_all_caps_identifier(text)
            }
            "number_literal" => true,
            "binary_expression" => {
                // Both operands must be ALL_CAPS arithmetic
                node.child_by_field_name("left")
                    .is_some_and(|l| Self::is_all_caps_arithmetic(&l, source))
                    && node
                        .child_by_field_name("right")
                        .is_some_and(|r| Self::is_all_caps_arithmetic(&r, source))
            }
            "parenthesized_expression" => {
                // Unwrap parentheses
                node.child(1)
                    .is_some_and(|inner| Self::is_all_caps_arithmetic(&inner, source))
            }
            _ => false,
        }
    }

    fn is_pointer_scaled_arithmetic(&self, left: &Node, right: &Node, source: &str) -> bool {
        let left_text = &source[left.start_byte()..left.end_byte()];
        let right_text = &source[right.start_byte()..right.end_byte()];

        // Both operands are ALL_CAPS identifiers → macro/enum constants, not pointers
        if Self::is_all_caps_identifier(left_text) && Self::is_all_caps_identifier(right_text) {
            return false;
        }

        // Entire expression tree consists of ALL_CAPS identifiers and numeric literals
        // (handles nested expressions like `A + B + C` parsed as `(A + B) + C`)
        if Self::is_all_caps_arithmetic(left, source) && Self::is_all_caps_arithmetic(right, source)
        {
            return false;
        }

        // Check if left is likely a pointer and right contains scaling
        let left_is_pointer = self.looks_like_pointer_node(left, source);
        let right_is_scaled = self.is_scaled_integer_expression(&right, source);

        // If it's a char pointer (by naming or cast), byte arithmetic is correct
        // (not a violation) — UNLESS the offset is itself scaled by sizeof(char)
        // (or a signed/unsigned char variant). That multiplication is always a
        // no-op (sizeof(char) == 1) regardless of the pointer's type, so it's
        // its own anti-pattern rather than the double-scaling this exemption
        // is meant to allow.
        let scaled_by_char_size = Self::scaled_by_char_size(right, source);
        if left_is_pointer
            && !scaled_by_char_size
            && (self.is_char_pointer(left, source) || left_text.to_lowercase().contains("byte"))
        {
            return false;
        }

        // Special case: generic pointer name with offset/skip variable suggests intentional byte arithmetic
        // This is a heuristic to avoid false positives when char* pointers are used
        if left_text == "ptr" && (right_text == "skip" || right_text == "offset") {
            return false; // Likely intentional byte-level arithmetic
        }

        left_is_pointer && right_is_scaled
    }

    /// Whether `right` scales by `sizeof` a character type, always 1: its
    /// own anti-pattern whatever the pointer's type.
    fn scaled_by_char_size(right: &Node, source: &str) -> bool {
        let right_text = ast_utils::get_node_text(right, source);
        right_text.contains("sizeof(char)")
            || right_text.contains("sizeof(unsigned char)")
            || right_text.contains("sizeof(signed char)")
    }

    /// Whether `node` is a byte count: a `sizeof` or `offsetof`, a product
    /// or sum with one in it, or a name that holds one. A quotient is one
    /// only when its dividend is, since a `sizeof` that divides turns a
    /// byte count into an element count (`len / sizeof(long)`).
    fn is_scaled_integer_expression(&self, node: &Node, source: &str) -> bool {
        Self::is_byte_count(node, source, true)
    }

    /// [`Self::is_scaled_integer_expression`], with `whole` saying whether
    /// `node` is the whole offset: a bare `skip` or `offset` counts only
    /// then, and not as one term of a sum or product.
    fn is_byte_count(node: &Node, source: &str, whole: bool) -> bool {
        match node.kind() {
            "parenthesized_expression" => {
                return node
                    .named_child(0)
                    .is_some_and(|inner| Self::is_byte_count(&inner, source, whole));
            }
            "binary_expression" => {
                let operator = node
                    .child_by_field_name("operator")
                    .map(|o| ast_utils::get_node_text(&o, source));
                let side = |field| {
                    node.child_by_field_name(field)
                        .is_some_and(|o| Self::is_byte_count(&o, source, false))
                };
                match operator {
                    Some("/" | "%") => return side("left"),
                    Some("*" | "+" | "-") => return side("left") || side("right"),
                    _ => {}
                }
            }
            _ => {}
        }
        let text = &source[node.start_byte()..node.end_byte()];

        // Common scaled integer patterns - direct sizeof/offsetof
        if text.contains("sizeof(")
            || text.contains("offsetof(")
            || (text.contains("*") && (text.contains("sizeof") || text.contains("wcslen")))
            || text.contains("wcslen(") && text.contains("sizeof(wchar_t)")
        {
            return true;
        }

        // Check for variables that likely hold byte counts/sizes
        // These are common patterns where byte values are incorrectly used for pointer arithmetic
        let lower = text.to_lowercase();
        lower.contains("_size")
            || lower.contains("alloc_size")
            || lower.contains("byte_offset")
            || (whole && lower == "skip") // offsetof result variable name from wiki example
            || (whole && lower == "offset") // Common offset variable
            || lower.contains("_bytes")
            || lower.contains("offset_bytes")
    }

    fn looks_like_pointer(&self, node: &Node, source: &str) -> bool {
        let text = &source[node.start_byte()..node.end_byte()];
        let lower = text.to_lowercase();

        // Simple heuristics for pointer identification (case-insensitive)
        lower.ends_with("_ptr")
            || text.ends_with("*")
            || lower.contains("pointer")
            || lower.contains("buf")
            || lower.contains("array")
            || lower.contains("ptr")
            || lower.contains("start")
            || lower.contains("end")
            || text == "s"
            || text == "p"
            || lower.contains("data")
            || lower.contains("dest")
            || lower.contains("src")
            || lower.contains("message")
            || lower.contains("record")
            || lower.contains("append")
    }

    fn is_char_pointer(&self, node: &Node, source: &str) -> bool {
        // Check if this is a char-type pointer (which is allowed to use byte arithmetic)

        // For an identifier, we need to look at its declaration or most recent cast
        // This is a simplified heuristic - we look for cast expressions in the parent chain
        // Walk up the tree to find casts, up to 5 levels: the ancestors come
        // from one descent ([`ast_utils::ancestors`]), since a `parent()`
        // step costs the node's depth.
        for parent in ast_utils::ancestors(node).take(5) {
            // Check for char* / u8* / uint8_t* casts
            if parent.kind() == "cast_expression" {
                if let Some(type_node) = parent.child_by_field_name("type") {
                    let type_text = ast_utils::get_node_text(&type_node, source);
                    if Self::is_byte_type(type_text) {
                        return true;
                    }
                }
            }
        }

        // No cast in the ancestor chain (e.g. `charPointer` used bare, several
        // statements after `char *charPointer = (char *)intArray;`). Fall back
        // to the variable's actual declared type instead of relying on a cast
        // to be present at every use site. Uses the same scope/shadowing-aware
        // lookup as the rest of the codebase (ast_utils), not a flat whole-file
        // scan -- two different functions with same-named locals of different
        // types must not be conflated.
        if node.kind() == "identifier" {
            let name = &source[node.start_byte()..node.end_byte()];

            if let Some(decl) = ast_utils::find_enclosing_declaration_for_identifier_in(
                &ast_utils::tree_root(node),
                node,
                name,
                source,
            ) {
                if let Some((type_text, is_pointer)) =
                    Self::declaration_type_for_name(&decl, name, source)
                {
                    if is_pointer && Self::is_byte_type(&type_text) {
                        return true;
                    }
                }
            } else if let Some(func) = ast_utils::find_containing_function(node) {
                // Not a local declaration -- check whether it's a parameter.
                if let Some(params) = ast_utils::get_function_parameters(&func, source) {
                    if let Some((_, param_type)) = params.iter().find(|(n, _)| n == name) {
                        if ast_utils::is_pointer_type(param_type) && Self::is_byte_type(param_type)
                        {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Given a `declaration` node known to bind `name` (per
    /// `ast_utils::find_enclosing_declaration_for_identifier`), return its
    /// type text and whether that specific declarator is a pointer/array.
    /// Handles comma-separated multi-declarator declarations (`char *a, b;`)
    /// where declarators can differ in pointer-ness.
    fn declaration_type_for_name(decl: &Node, name: &str, source: &str) -> Option<(String, bool)> {
        let type_text = ast_utils::declaration_type_text(decl, source);

        for i in 0..decl.child_count() {
            let Some(child) = decl.child(i) else { continue };
            let declarator = match child.kind() {
                "init_declarator" => child.child_by_field_name("declarator").unwrap_or(child),
                "identifier"
                | "pointer_declarator"
                | "array_declarator"
                | "function_declarator" => child,
                _ => continue,
            };
            if get_identifier_from_declarator(&declarator, source) == name {
                let is_pointer =
                    is_pointer_declarator(&declarator) || is_array_declarator(&declarator);
                return Some((type_text, is_pointer));
            }
        }
        None
    }

    /// Returns true for single-byte pointer types: char*, unsigned char*, u8*, uint8_t*, etc.
    fn is_byte_type(type_text: &str) -> bool {
        let t = type_text.trim();
        // Standard char types
        if (t.contains("char") && !t.contains("wchar"))
            || t.contains("unsigned char")
            || t.contains("signed char")
        {
            return true;
        }
        // Embedded/vendor byte aliases
        matches!(t, "u8" | "uint8_t" | "UINT8" | "uint8_T" | "byte" | "BYTE")
    }

    fn looks_like_pointer_node(&self, node: &Node, source: &str) -> bool {
        match node.kind() {
            "identifier" => {
                let _text = &source[node.start_byte()..node.end_byte()];
                self.looks_like_pointer(node, source)
            }
            "binary_expression" => {
                // Could be pointer arithmetic
                true
            }
            "cast_expression" => {
                // Cast expressions are often pointers
                let text = &source[node.start_byte()..node.end_byte()];
                text.contains("*") // Has pointer in cast
            }
            _ => false,
        }
    }

    fn is_scaled_offset_pattern(&self, text: &str) -> bool {
        (text.contains("offsetof(") && text.contains("*"))
            || (text.contains("offsetof(") && text.contains("sizeof("))
    }

    fn has_scaled_pointer_comparison(&self, node: &Node, source: &str) -> bool {
        let text = &source[node.start_byte()..node.end_byte()];

        // Look for patterns like: ptr < (buf + sizeof(buf))
        text.contains("sizeof(")
            && (text.contains(" < ")
                || text.contains(" <= ")
                || text.contains(" > ")
                || text.contains(" >= "))
            && (text.contains(" + ") || text.contains(" - "))
    }

    fn find_loop_condition<'a>(&self, node: &'a Node<'a>) -> Option<Node<'a>> {
        // Find condition in while or for loop
        match node.kind() {
            "while_statement" => node.child_by_field_name("condition"),
            "for_statement" => node.child_by_field_name("condition"),
            _ => None,
        }
    }

    fn get_operator(&self, node: &Node, source: &str) -> Option<String> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let text = &source[child.start_byte()..child.end_byte()];
                if matches!(text, "+" | "-" | "*" | "/") {
                    return Some(text.to_string());
                }
            }
        }
        None
    }

    fn get_assignment_operator(&self, node: &Node, source: &str) -> Option<String> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let text = &source[child.start_byte()..child.end_byte()];
                if matches!(text, "+=" | "-=" | "*=" | "/=") {
                    return Some(text.to_string());
                }
            }
        }
        None
    }

    fn get_function_arguments(&self, node: &Node, source: &str) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(arguments) = node.child_by_field_name("arguments") {
            for i in 0..arguments.child_count() {
                if let Some(child) = arguments.child(i) {
                    if child.kind() != "," {
                        let arg_text = source[child.start_byte()..child.end_byte()].to_string();
                        args.push(arg_text);
                    }
                }
            }
        }

        args
    }
}
