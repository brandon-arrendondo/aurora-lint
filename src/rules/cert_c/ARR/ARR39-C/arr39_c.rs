// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::{ProjectContext, VisibleTypes};
use crate::manifest::Severity;
use crate::settings::{AnalysisSettings, IntFacts};
use crate::utility::cert_c::ast_utils;
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
            defined_records: OnceCell::new(),
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
    /// The tags of the structs and unions this file defines with a body.
    defined_records: OnceCell<HashSet<String>>,
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

    /// The element type a pointer or array `operand` steps over, when its
    /// declarations say: through the expression typer, or the project's
    /// pointer objects for a name no declaration in the file binds. A sum or
    /// difference the typer cannot type, because an integer operand's type
    /// is not fixed (`p + n * sizeof(x)` where the data model leaves
    /// `size_t`'s rank open), has its pointer operand's element.
    fn element_type(&self, operand: &Node) -> Option<CType> {
        let typed = expr_type::expr_type(operand, self.source, self.env())
            .or_else(|| self.project_object_type(operand));
        match typed {
            Some(CType::Pointer(element) | CType::Array(element)) => element.map(|e| *e),
            Some(_) => None,
            None => match operand.kind() {
                "parenthesized_expression" => operand
                    .named_child(0)
                    .and_then(|inner| self.element_type(&inner)),
                "binary_expression" => {
                    let operator = operand
                        .child_by_field_name("operator")
                        .map(|o| ast_utils::get_node_text(&o, self.source));
                    if !matches!(operator, Some("+" | "-")) {
                        return None;
                    }
                    ["left", "right"].iter().find_map(|side| {
                        operand
                            .child_by_field_name(side)
                            .and_then(|o| self.element_type(&o))
                    })
                }
                _ => None,
            },
        }
    }

    /// Whether `operand` is a pointer or array whose element type is known
    /// and wider than a byte, so that adding a byte count to it scales the
    /// count a second time. A character type, an exactly 8-bit integer and
    /// `void` (which GNU C moves by bytes) step by one byte. An element the
    /// declarations leave unknown, or an integer type that may be a single
    /// byte, gives no finding: like [`Self::is_pointer`], this answers only
    /// what the declarations show. So does a struct or union whose
    /// definition the file does not see, as when its header is missing. A `wchar_t` element steps by
    /// `sizeof(wchar_t)`, which only a declared `wchar_t_bits` fixes.
    fn steps_by_elements(&self, operand: &Node) -> bool {
        if !self.is_pointer(operand) {
            return false;
        }
        match self.element_type(operand) {
            None => self.declares_wide_char_elements(operand),
            Some(
                CType::Int {
                    rank: Rank::Char, ..
                }
                | CType::IntOfWidth {
                    max_bits: Some(8), ..
                }
                | CType::Void
                | CType::Function(_),
            ) => false,
            Some(CType::IntOfWidth {
                min_bits,
                max_bits: None,
                ..
            }) => min_bits > 8,
            Some(CType::Record(Some(tag))) => self.defines_record(&tag),
            Some(_) => true,
        }
    }

    /// Whether a definition of the struct or union `tag` is visible: one the
    /// project's field tables file (a struct, from this file or a header),
    /// or a `struct`/`union` specifier with a body in this file.
    fn defines_record(&self, tag: &str) -> bool {
        self.visible.struct_field_shapes.contains_key(tag)
            || self.visible.struct_field_types.contains_key(tag)
            || self
                .defined_records
                .get_or_init(|| {
                    query::find_descendants_of_kinds(
                        self.root,
                        &["struct_specifier", "union_specifier"],
                    )
                    .into_iter()
                    .filter(|s| s.child_by_field_name("body").is_some())
                    .filter_map(|s| s.child_by_field_name("name"))
                    .map(|n| ast_utils::get_node_text(&n, self.source).to_string())
                    .collect()
                })
                .contains(tag)
    }

    /// Whether `operand` names an object its declaration gives `wchar_t`
    /// elements (`wchar_t *p`, `wchar_t buf[N]`) and the data model makes a
    /// `wchar_t` wider than a byte. The typer leaves `wchar_t` untyped, since
    /// its width is a platform fact the integer widths do not carry.
    fn declares_wide_char_elements(&self, operand: &Node) -> bool {
        let operand = Arr39C::unparenthesized(*operand);
        operand.kind() == "identifier"
            && self.model.wchar_bytes().is_some_and(|bytes| bytes > 1)
            && ast_utils::resolve_identifier_declared_type(
                &operand,
                ast_utils::get_node_text(&operand, self.source),
                self.source,
            )
            .is_some_and(|spelled| spelled == "wchar_t *")
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
                    self.check_loop_pointer_arithmetic(&matched, source, types, violations);
                }
                "subscript_expression" => {
                    // Check for violations in array subscript like ptr[scaled_value]
                    self.check_subscript_scaling(&matched, source, types, violations);
                }
                _ => {}
            }
        }
    }

    /// Whether adding `offset` to `pointer` scales twice: `offset` is a
    /// byte count by its structure ([`Self::is_byte_count`]) and `pointer`
    /// steps by elements wider than a byte.
    fn adds_byte_count(
        &self,
        pointer: &Node,
        offset: &Node,
        source: &str,
        types: &OperandTypes,
    ) -> bool {
        self.is_byte_count(offset, source, 0) && types.steps_by_elements(pointer)
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
                    if self.adds_byte_count(&left, &right, source, types) {
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
                    if self.adds_byte_count(&left, &right, source, types) {
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
        // `ptr[byte_count]`: the subscript scales the index as `ptr + index` does.
        if let (Some(argument), Some(index)) = (
            node.child_by_field_name("argument"),
            node.child_by_field_name("index"),
        ) {
            if self.adds_byte_count(&argument, &index, source, types) {
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
        types: &OperandTypes,
        violations: &mut Vec<RuleViolation>,
    ) {
        let Some(condition) = self.find_loop_condition(node) else {
            return;
        };
        // `for (i = 0; i < sizeof(data); i++) { ptr[i] ... }`: the counter
        // runs to a byte count and steps a pointer by elements.
        if let Some(counter) = self.counter_bounded_by_byte_count(&condition, source) {
            if let Some(body) = self.find_loop_body(node) {
                if self.steps_by_counter(&body, &counter, source, types) {
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

        // `while (ptr < buf + sizeof(buf))`: the bound itself adds a byte
        // count to a pointer that steps by elements.
        if self.compares_against_scaled_pointer(&condition, source, types) {
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

    fn find_loop_body<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        match node.kind() {
            "for_statement" => node.child_by_field_name("body"),
            "while_statement" => node.child_by_field_name("body"),
            "do_statement" => node.child_by_field_name("body"),
            _ => None,
        }
    }

    /// The counter a loop condition compares with a byte count (`i <
    /// sizeof(data)`, `sizeof(data) > i`), when one side is a plain name and
    /// the other a byte count by its structure.
    fn counter_bounded_by_byte_count<'t>(
        &self,
        condition: &Node<'t>,
        source: &str,
    ) -> Option<Node<'t>> {
        let condition = Self::unparenthesized(*condition);
        if condition.kind() != "binary_expression" {
            return None;
        }
        let operator = condition
            .child_by_field_name("operator")
            .map(|o| ast_utils::get_node_text(&o, source))?;
        let (left, right) = (
            condition.child_by_field_name("left")?,
            condition.child_by_field_name("right")?,
        );
        let (counter, bound) = match operator {
            "<" | "<=" | "!=" => (left, right),
            ">" | ">=" => (right, left),
            _ => return None,
        };
        (counter.kind() == "identifier" && self.is_byte_count(&bound, source, 0)).then_some(counter)
    }

    /// Whether `body` steps a pointer of elements wider than a byte by the
    /// loop's `counter`: `ptr[i]`, `ptr + i` or `*(ptr + i)`, with `i` the
    /// counter's own declaration (ADR-0006).
    fn steps_by_counter(
        &self,
        body: &Node,
        counter: &Node,
        source: &str,
        types: &OperandTypes,
    ) -> bool {
        let name = ast_utils::get_node_text(counter, source);
        let binding = ast_utils::resolve_identifier_declarator(counter, name, source)
            .map(|(_, declarator)| declarator.id());
        let is_counter = |node: &Node| {
            let node = Self::unparenthesized(*node);
            node.kind() == "identifier"
                && ast_utils::get_node_text(&node, source) == name
                && ast_utils::resolve_identifier_declarator(&node, name, source)
                    .map(|(_, declarator)| declarator.id())
                    == binding
        };
        query::find_first_descendant(*body, |node| match node.kind() {
            "subscript_expression" => {
                node.child_by_field_name("index")
                    .is_some_and(|i| is_counter(&i))
                    && node
                        .child_by_field_name("argument")
                        .is_some_and(|a| types.steps_by_elements(&a))
            }
            "binary_expression" => {
                matches!(
                    node.child_by_field_name("operator")
                        .map(|o| ast_utils::get_node_text(&o, source)),
                    Some("+" | "-")
                ) && node
                    .child_by_field_name("right")
                    .is_some_and(|r| is_counter(&r))
                    && node
                        .child_by_field_name("left")
                        .is_some_and(|l| types.steps_by_elements(&l))
            }
            _ => false,
        })
        .is_some()
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

    /// `node` with any parentheses around it taken off.
    fn unparenthesized(node: Node) -> Node {
        let mut node = node;
        while node.kind() == "parenthesized_expression" {
            match node.named_child(0) {
                Some(inner) => node = inner,
                None => break,
            }
        }
        node
    }

    /// Whether `node`, parentheses aside, is a `sizeof` or an `offsetof`.
    fn is_size_operator(node: &Node, source: &str) -> bool {
        let node = Self::unparenthesized(*node);
        match node.kind() {
            "sizeof_expression" | "offsetof_expression" => true,
            // `offsetof` the parser reads as a call: spelled through a macro
            // of the same name, or with arguments it cannot take as a type.
            "call_expression" => node
                .child_by_field_name("function")
                .is_some_and(|f| ast_utils::get_node_text(&f, source) == "offsetof"),
            _ => false,
        }
    }

    /// Whether `node` is a byte count by its structure, never by a name
    /// (ADR-0006): a `sizeof` or `offsetof`, a product, sum or difference
    /// with one in it, a cast or a conditional of one, or a local assigned
    /// only by its initializer, which is one (`size_t skip = offsetof(...)`).
    /// A quotient is one when its dividend is one and its divisor is not,
    /// since dividing a byte count by a size gives an element count (`len /
    /// sizeof(long)`, `sizeof(buf) / sizeof(buf[0])`). A remainder is one
    /// when its dividend is, or when it is taken by a `sizeof` or
    /// `offsetof`: `len % sizeof(int)` is the bytes left over. `depth`
    /// bounds the walk through locals' initializers.
    fn is_byte_count(&self, node: &Node, source: &str, depth: usize) -> bool {
        let node = Self::unparenthesized(*node);
        match node.kind() {
            "sizeof_expression" | "offsetof_expression" => true,
            "call_expression" => Self::is_size_operator(&node, source),
            "cast_expression" => node
                .child_by_field_name("value")
                .is_some_and(|v| self.is_byte_count(&v, source, depth)),
            "conditional_expression" => ["consequence", "alternative"].iter().any(|field| {
                node.child_by_field_name(field)
                    .is_some_and(|o| self.is_byte_count(&o, source, depth))
            }),
            "binary_expression" => {
                let operator = node
                    .child_by_field_name("operator")
                    .map(|o| ast_utils::get_node_text(&o, source));
                let side = |field| {
                    node.child_by_field_name(field)
                        .is_some_and(|o| self.is_byte_count(&o, source, depth))
                };
                match operator {
                    Some("/") => side("left") && !side("right"),
                    Some("%") => {
                        side("left")
                            || node
                                .child_by_field_name("right")
                                .is_some_and(|o| Self::is_size_operator(&o, source))
                    }
                    Some("*" | "+" | "-") => side("left") || side("right"),
                    _ => false,
                }
            }
            "identifier" if depth < 4 => Self::sole_initializer(&node, source)
                .is_some_and(|value| self.is_byte_count(&value, source, depth + 1)),
            _ => false,
        }
    }

    /// The initializer of the local `ident` names, when nothing else in its
    /// function assigns it, steps it or takes its address: then its value
    /// wherever it is read is that initializer's.
    fn sole_initializer<'t>(ident: &Node<'t>, source: &str) -> Option<Node<'t>> {
        let name = ast_utils::get_node_text(ident, source);
        let (declaration, declarator) =
            ast_utils::resolve_identifier_declarator(ident, name, source)?;
        if declaration.kind() != "declaration"
            || !ast_utils::ancestors(&declaration).any(|a| a.kind() == "compound_statement")
        {
            return None;
        }
        let init = if declarator.kind() == "init_declarator" {
            declarator
        } else {
            declarator
                .parent()
                .filter(|p| p.kind() == "init_declarator")?
        };
        let value = init.child_by_field_name("value")?;
        let function = ast_utils::find_containing_function(&declaration)?;
        let written = query::find_first_descendant(function, |node| {
            let target = match node.kind() {
                "assignment_expression" => node.child_by_field_name("left"),
                "update_expression" => node.child_by_field_name("argument"),
                "pointer_expression" => node
                    .child_by_field_name("operator")
                    .filter(|o| ast_utils::get_node_text(o, source) == "&")
                    .and_then(|_| node.child_by_field_name("argument")),
                _ => None,
            };
            target.map(Self::unparenthesized).is_some_and(|t| {
                t.kind() == "identifier"
                    && ast_utils::get_node_text(&t, source) == name
                    && ast_utils::resolve_identifier_declarator(&t, name, source)
                        .is_some_and(|(_, d)| d.id() == declarator.id())
            })
        });
        written.is_none().then_some(value)
    }

    fn is_scaled_offset_pattern(&self, text: &str) -> bool {
        (text.contains("offsetof(") && text.contains("*"))
            || (text.contains("offsetof(") && text.contains("sizeof("))
    }

    /// Whether a loop `condition` compares against a pointer to which a byte
    /// count is added (`ptr < buf + sizeof(buf)`).
    fn compares_against_scaled_pointer(
        &self,
        condition: &Node,
        source: &str,
        types: &OperandTypes,
    ) -> bool {
        query::find_first_descendant(*condition, |node| {
            node.kind() == "binary_expression"
                && matches!(
                    node.child_by_field_name("operator")
                        .map(|o| ast_utils::get_node_text(&o, source)),
                    Some("<" | "<=" | ">" | ">=")
                )
                && ["left", "right"].iter().any(|field| {
                    node.child_by_field_name(field).is_some_and(|side| {
                        let side = Self::unparenthesized(side);
                        side.kind() == "binary_expression"
                            && matches!(
                                side.child_by_field_name("operator")
                                    .map(|o| ast_utils::get_node_text(&o, source)),
                                Some("+" | "-")
                            )
                            && match (
                                side.child_by_field_name("left"),
                                side.child_by_field_name("right"),
                            ) {
                                (Some(l), Some(r)) => self.adds_byte_count(&l, &r, source, types),
                                _ => false,
                            }
                    })
                })
        })
        .is_some()
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
