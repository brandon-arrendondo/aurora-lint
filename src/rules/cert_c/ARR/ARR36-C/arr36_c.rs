use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Arr36C;

impl CertRule for Arr36C {
    fn rule_id(&self) -> &'static str {
        "ARR36-C"
    }

    fn description(&self) -> &'static str {
        "Do not subtract or compare two pointers that do not refer to the same array"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "ARR36-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Per-function analysis: create a fresh PointerAnalyzer for each function
        // to avoid cross-function variable name collisions.
        self.visit_functions(node, source, &mut violations);

        violations
    }
}

impl Arr36C {
    /// Walk the AST to find function_definition nodes, then analyze each independently.
    /// File-scope declarations (globals) are collected first and shared across all functions.
    fn visit_functions(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // First pass: collect file-scope declarations (global arrays, static vars)
        let mut file_scope = PointerAnalyzer::new();
        file_scope.collect_file_scope(node, source);

        // Second pass: per-function analysis with file-scope as base
        let funcs = query::find_descendants_of_kind(*node, "function_definition");
        let analyzers: Vec<PointerAnalyzer> = funcs
            .iter()
            .map(|func| {
                let mut analyzer = PointerAnalyzer::from(&file_scope);
                analyzer.collect_declarations(func, source);
                analyzer
            })
            .collect();

        // Callers before callees: two pointer PARAMETERS are reported as
        // different arrays only when a call site in this file proves they are,
        // so every call site has to be read first (see `CallSiteBases`).
        let mut call_sites = CallSiteBases::default();
        for (func, analyzer) in funcs.iter().zip(&analyzers) {
            call_sites.collect_from(func, source, analyzer);
        }

        for (func, analyzer) in funcs.iter().zip(&analyzers) {
            let frame = FrameContext {
                function_name: function_name_of(func, source),
                param_indices: parameter_indices(func, source),
                call_sites: &call_sites,
            };
            self.check_node(func, source, analyzer, &frame, violations);
        }
    }

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        analyzer: &PointerAnalyzer,
        frame: &FrameContext,
        violations: &mut Vec<RuleViolation>,
    ) {
        for binary_expr in query::find_descendants_of_kind(*node, "binary_expression") {
            self.check_binary_expression(&binary_expr, source, analyzer, frame, violations);
        }
    }

    fn check_binary_expression(
        &self,
        node: &Node,
        source: &str,
        analyzer: &PointerAnalyzer,
        frame: &FrameContext,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(operator) = get_operator(node, source) {
            match operator.as_str() {
                "-" => {
                    self.check_pointer_subtraction(node, source, analyzer, frame, violations);
                }
                "<" | "<=" | ">" | ">=" => {
                    self.check_pointer_comparison(node, source, analyzer, frame, violations);
                }
                _ => {}
            }
        }
    }

    fn check_pointer_subtraction(
        &self,
        node: &Node,
        source: &str,
        analyzer: &PointerAnalyzer,
        frame: &FrameContext,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let left_info = analyzer.get_pointer_info(&left, source);
            let right_info = analyzer.get_pointer_info(&right, source);

            if let (Some(left_array), Some(right_array)) = (left_info, right_info) {
                if left_array != right_array && frame.reportable(&left_array, &right_array) {
                    let start_point = node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Pointer subtraction between pointers from different arrays: '{}' and '{}'",
                            left_array, right_array
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Ensure both pointers refer to the same array before subtraction".to_string()),
                        ..Default::default()
                    });
                }
            }
        }
    }

    fn check_pointer_comparison(
        &self,
        node: &Node,
        source: &str,
        analyzer: &PointerAnalyzer,
        frame: &FrameContext,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let left_info = analyzer.get_pointer_info(&left, source);
            let right_info = analyzer.get_pointer_info(&right, source);

            if let (Some(left_array), Some(right_array)) = (left_info, right_info) {
                if left_array != right_array && frame.reportable(&left_array, &right_array) {
                    let start_point = node.start_position();
                    let op = get_operator(node, source).unwrap_or("?".to_string());
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Pointer comparison '{}' between pointers from different arrays: '{}' and '{}'",
                            op, left_array, right_array
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Ensure both pointers refer to the same array before comparison".to_string()),
                        ..Default::default()
                    });
                }
            }
        }
    }
}

/// What one function's frame knows about its own parameters, used to decide
/// whether a parameter-vs-parameter report is warranted at all.
struct FrameContext<'a> {
    /// This function's name, when its declarator gives one. Call sites are
    /// matched to it by name, which is exact within one translation unit.
    function_name: Option<String>,
    /// Parameter name -> position in the parameter list, for every parameter
    /// of THIS function, pointer or not: an argument's position has to line
    /// up with the whole list.
    param_indices: HashMap<String, usize>,
    call_sites: &'a CallSiteBases,
}

impl FrameContext<'_> {
    /// Whether a mismatched base pair is a violation this frame can claim.
    ///
    /// A pointer parameter's base is synthetic (`param:name`), so two
    /// distinct parameters ALWAYS compare unequal -- which made every
    /// `(u8 **pos, u8 *end)` bounds check a violation even though the caller
    /// derives both from one buffer. Nothing inside the function settles it;
    /// the fact lives in the caller. So the default is inverted here: two
    /// parameters are taken to share an object unless a call site in this
    /// file passes two provably distinct objects (task 753). Every other base
    /// pair is unaffected -- a local array against a parameter is still
    /// decided inside the frame that declares it.
    fn reportable(&self, left: &str, right: &str) -> bool {
        let (Some(left), Some(right)) = (self.own_param_index(left), self.own_param_index(right))
        else {
            return true;
        };
        match &self.function_name {
            Some(name) => self.call_sites.proves_distinct(name, left, right),
            None => false,
        }
    }

    /// Position of the parameter a `param:` base names, when it is a
    /// parameter of this function. `collect_declarations` also records
    /// parameters of nested declarators (a function-pointer parameter's own
    /// parameters), which are not in this list and yield `None`.
    fn own_param_index(&self, base: &str) -> Option<usize> {
        self.param_indices
            .get(base.strip_prefix("param:")?)
            .copied()
    }
}

/// Every direct call in this file, by callee name, recording which storage
/// OBJECT each argument denotes.
///
/// This is the caller-side fact the parameter model needs, gathered in the
/// only frame `check()` actually has. It is deliberately file-local: a callee
/// whose callers all live in other translation units has no proof here, and
/// its parameters stay assumed to share an object. Closing that gap needs the
/// same predicate computed during prescan.
#[derive(Default)]
struct CallSiteBases {
    per_callee: HashMap<String, Vec<Vec<Option<String>>>>,
}

impl CallSiteBases {
    /// Record every direct call in `func`, resolving each argument in the
    /// CALLER's own frame (`analyzer`).
    fn collect_from(&mut self, func: &Node, source: &str, analyzer: &PointerAnalyzer) {
        for call in query::find_descendants_of_kind(*func, "call_expression") {
            let (Some(callee), Some(args)) = (
                call.child_by_field_name("function"),
                call.child_by_field_name("arguments"),
            ) else {
                continue;
            };
            // Only a name resolves to a definition in this file; `obj->cb(...)`
            // is opaque.
            if callee.kind() != "identifier" {
                continue;
            }
            let bases = argument_nodes(&args)
                .iter()
                .map(|arg| analyzer.argument_object_base(arg, source))
                .collect();
            self.per_callee
                .entry(ast_utils::get_node_text(&callee, source).to_string())
                .or_default()
                .push(bases);
        }
    }

    /// True if some call site passes two named, DIFFERENT storage objects at
    /// positions `left` and `right`. One such call site is enough: if any
    /// caller passes two distinct arrays, the comparison inside the callee is
    /// undefined whenever that caller's path runs.
    fn proves_distinct(&self, callee: &str, left: usize, right: usize) -> bool {
        let Some(sites) = self.per_callee.get(callee) else {
            return false;
        };
        sites
            .iter()
            .any(|args| match (args.get(left), args.get(right)) {
                (Some(Some(left)), Some(Some(right))) => left != right,
                _ => false,
            })
    }
}

/// The argument expressions of a call, in order. `argument_list` also holds
/// the parentheses and commas, which are unnamed, and any comment between
/// arguments.
fn argument_nodes<'tree>(args: &Node<'tree>) -> Vec<Node<'tree>> {
    (0..args.child_count())
        .filter_map(|i| args.child(i))
        .filter(|child| child.is_named() && child.kind() != "comment")
        .collect()
}

/// Name of a function definition, from its (possibly pointer-wrapped)
/// declarator.
fn function_name_of(func: &Node, source: &str) -> Option<String> {
    let declarator = func.child_by_field_name("declarator")?;
    let name = ast_utils::get_identifier_from_declarator(&declarator, source);
    (!name.is_empty()).then_some(name)
}

/// This function's parameter names, mapped to their position in the parameter
/// list. Unnamed parameters (`void`, an abstract declarator) still consume a
/// position, so the count has to include them.
fn parameter_indices(func: &Node, source: &str) -> HashMap<String, usize> {
    let mut indices = HashMap::new();
    let Some(declarator) = func.child_by_field_name("declarator") else {
        return indices;
    };
    // Pre-order, so the function's own list comes before any list belonging to
    // a function-pointer parameter.
    let Some(list) = query::find_descendants_of_kind(declarator, "parameter_list")
        .first()
        .copied()
    else {
        return indices;
    };
    let params = (0..list.child_count())
        .filter_map(|i| list.child(i))
        .filter(|child| child.kind() == "parameter_declaration");
    for (position, param) in params.enumerate() {
        if let Some(param_declarator) = param.child_by_field_name("declarator") {
            let name = ast_utils::get_identifier_from_declarator(&param_declarator, source);
            if !name.is_empty() {
                indices.insert(name, position);
            }
        }
    }
    indices
}

struct PointerAnalyzer {
    // Maps variable names to their array base (for tracking which array they belong to)
    variable_arrays: HashMap<String, String>,
    // Every name DECLARED as a pointer or array, whether or not its base is
    // known. `variable_arrays` answers "which array is this in"; this answers
    // the prior question of whether the name can be in an array at all.
    pointer_vars: HashSet<String>,
    // Names declared with an array declarator -- `char buf[N]` -- and so
    // naming storage of their own. A pointer variable is NOT in here however
    // well its base is known, because only a declaration of storage settles
    // which object an argument hands to a callee (see
    // `argument_object_base`).
    array_objects: HashSet<String>,
}

impl PointerAnalyzer {
    fn new() -> Self {
        Self {
            variable_arrays: HashMap::new(),
            pointer_vars: HashSet::new(),
            array_objects: HashSet::new(),
        }
    }

    fn from(base: &PointerAnalyzer) -> Self {
        Self {
            variable_arrays: base.variable_arrays.clone(),
            pointer_vars: base.pointer_vars.clone(),
            array_objects: base.array_objects.clone(),
        }
    }

    /// Collect file-scope declarations (globals, statics at file level).
    /// Only processes direct children of translation_unit and preproc blocks.
    fn collect_file_scope(&mut self, node: &Node, source: &str) {
        match node.kind() {
            "translation_unit" | "preproc_ifdef" | "preproc_if" | "preproc_else"
            | "preproc_elif" => {
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "declaration" {
                            self.process_declaration(&child, source);
                        } else if matches!(
                            child.kind(),
                            "preproc_ifdef" | "preproc_if" | "preproc_else" | "preproc_elif"
                        ) {
                            self.collect_file_scope(&child, source);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn collect_declarations(&mut self, node: &Node, source: &str) {
        let matches = query::find_descendants_of_kinds(
            *node,
            &[
                "declaration",
                "parameter_declaration",
                "expression_statement",
            ],
        );
        for n in matches {
            match n.kind() {
                "declaration" => {
                    self.process_declaration(&n, source);
                }
                "parameter_declaration" => {
                    self.process_parameter(&n, source);
                }
                "expression_statement" => {
                    self.process_assignment(&n, source);
                }
                _ => {}
            }
        }
    }

    fn process_declaration(&mut self, node: &Node, source: &str) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let declarator = if child.kind() == "init_declarator" {
                    child.child_by_field_name("declarator")
                } else if Self::is_pointer_declarator(&child) || child.kind() == "array_declarator"
                {
                    // Bare declarations without initializer: `int nums[SIZE];`, `int *p;`
                    Some(child)
                } else {
                    None
                };
                if let Some(declarator) = declarator {
                    if !Self::is_pointer_declarator(&declarator) {
                        continue;
                    }
                    let var_name = ast_utils::get_identifier_from_declarator(&declarator, source);
                    if var_name.is_empty() {
                        continue;
                    }
                    // Declared pointer or array. Recorded even when the base is
                    // unknown (a bare `int *p;`), because a later `p = buf;` is
                    // only trackable if we know p can hold a pointer at all.
                    self.pointer_vars.insert(var_name.clone());
                    // Array declarations create their own storage — the variable IS its own base.
                    if declarator.kind() == "array_declarator" {
                        self.array_objects.insert(var_name.clone());
                        self.variable_arrays.insert(var_name.clone(), var_name);
                        continue;
                    }
                    // Pointer with initializer: track which array it aliases
                    if child.kind() == "init_declarator" {
                        if let Some(value) = child.child_by_field_name("value") {
                            let array_base = self.extract_array_base(&value, source);
                            if !array_base.is_empty() {
                                self.variable_arrays.insert(var_name, array_base);
                            }
                        }
                    }
                    // Bare pointer declarations without initializer: not tracked
                    // (we don't know what they point to)
                }
            }
        }
    }

    /// Check if a declarator represents a pointer type (pointer_declarator or array_declarator).
    fn is_pointer_declarator(declarator: &Node) -> bool {
        matches!(declarator.kind(), "pointer_declarator" | "array_declarator")
    }

    fn process_parameter(&mut self, node: &Node, source: &str) {
        // For function parameters, only track pointer/array parameters as distinct arrays.
        // Non-pointer parameters (int, uint32_t, etc.) are scalars — comparing them
        // is not pointer comparison and should not trigger ARR36-C.
        if !self.is_pointer_or_array_parameter(node) {
            return;
        }
        if let Some(declarator) = node.child_by_field_name("declarator") {
            let param_name = ast_utils::get_identifier_from_declarator(&declarator, source);
            if !param_name.is_empty() {
                self.pointer_vars.insert(param_name.clone());
                // Use the parameter name itself as the "array base" to make it unique
                // This ensures parameters are only equal to themselves
                self.variable_arrays
                    .insert(param_name.clone(), format!("param:{}", param_name));
            }
        }
    }

    /// Process simple assignment expressions like `slashPtr = strchr(string1, '/')`.
    /// Tracks variables assigned from string-search functions (strchr, strrchr,
    /// wcschr, wcsrchr) as pointing into the first argument's array.
    /// Skips compound assignments (+=, -=) since those advance a pointer within
    /// the same array rather than changing which array it points to.
    fn process_assignment(&mut self, node: &Node, source: &str) {
        // expression_statement contains an assignment_expression child
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "assignment_expression" {
                    // Skip compound assignments (+=, -=, etc.) — they advance a pointer
                    // within the same array rather than changing which array it points to.
                    // tree-sitter puts the operator as a direct child: "=", "+=", "-=", etc.
                    let mut is_simple_assign = false;
                    for j in 0..child.child_count() {
                        if let Some(op) = child.child(j) {
                            if ast_utils::get_node_text(&op, source) == "=" {
                                is_simple_assign = true;
                                break;
                            }
                        }
                    }
                    if !is_simple_assign {
                        continue;
                    }
                    if let (Some(left), Some(right)) = (
                        child.child_by_field_name("left"),
                        child.child_by_field_name("right"),
                    ) {
                        let var_name = ast_utils::get_node_text(&left, source).to_string();
                        if var_name.is_empty()
                            || !var_name.chars().all(|c| c.is_alphanumeric() || c == '_')
                        {
                            continue;
                        }
                        // Only a declared pointer or array can be IN an array.
                        // Without this gate an ordinary scalar swap --
                        // `startAngle = endAngle; endAngle = tmp;` over three
                        // floats -- puts both names in `variable_arrays`, and the
                        // subtraction below them is then reported as pointer
                        // subtraction between different arrays (task 769).
                        if !self.pointer_vars.contains(&var_name) {
                            continue;
                        }
                        let array_base = self.extract_array_base(&right, source);
                        if !array_base.is_empty() {
                            self.variable_arrays.insert(var_name, array_base);
                        }
                    }
                }
            }
        }
    }

    /// Check if a parameter declaration is a pointer or array type.
    fn is_pointer_or_array_parameter(&self, param_node: &Node) -> bool {
        // Check declarator for pointer_declarator or array_declarator
        if let Some(declarator) = param_node.child_by_field_name("declarator") {
            if declarator.kind() == "pointer_declarator" || declarator.kind() == "array_declarator"
            {
                return true;
            }
            // Check children for nested pointer/array declarators
            for i in 0..declarator.child_count() {
                if let Some(child) = declarator.child(i) {
                    if child.kind() == "pointer_declarator" || child.kind() == "array_declarator" {
                        return true;
                    }
                }
            }
        }
        // Check if the type itself contains a pointer
        if let Some(type_node) = param_node.child_by_field_name("type") {
            // Abstract pointer declarators (e.g., `void *` without name)
            if type_node.kind() == "pointer_declarator" {
                return true;
            }
        }
        false
    }

    fn extract_array_base(&self, node: &Node, source: &str) -> String {
        let result = match node.kind() {
            "identifier" => {
                let name = source[node.start_byte()..node.end_byte()].to_string();
                // Follow alias chain: if this variable is already tracked, use its base.
                // This ensures `pos = buf` gives pos the same base as buf (e.g., "param:buf").
                // Untracked identifiers return the raw name — they may be typedef arrays
                // or extern variables that weren't collected.
                if let Some(base) = self.variable_arrays.get(&name) {
                    base.clone()
                } else {
                    name
                }
            }
            "field_expression" => {
                // Handle struct.member or union.member - capture full path
                // This ensures u.int_array and u.float_array are distinct
                source[node.start_byte()..node.end_byte()].to_string()
            }
            "cast_expression" => {
                // Handle cast expressions like (int *)malloc(...) - unwrap to get the underlying value
                if let Some(value) = node.child_by_field_name("value") {
                    self.extract_array_base(&value, source)
                } else {
                    String::new()
                }
            }
            "call_expression" => {
                // Check if this is a string-search function (strchr, strrchr, wcschr, wcsrchr)
                // whose return value points into the first argument
                if let Some(func_node) = node.child_by_field_name("function") {
                    let func_name = ast_utils::get_node_text(&func_node, source);
                    // Recognize standard string-search functions and common
                    // wrapper macros (os_strchr, os_strstr, etc.)
                    let canonical = func_name.strip_prefix("os_").unwrap_or(func_name);
                    if matches!(
                        canonical,
                        "strchr"
                            | "strrchr"
                            | "wcschr"
                            | "wcsrchr"
                            | "memchr"
                            | "strstr"
                            | "wcsstr"
                            | "strpbrk"
                            | "wcspbrk"
                    ) {
                        // Return value points into the first argument
                        if let Some(args) = node.child_by_field_name("arguments") {
                            // First real argument (skip '(' which is child 0)
                            for j in 0..args.child_count() {
                                if let Some(arg) = args.child(j) {
                                    if arg.kind() != "(" && arg.kind() != ")" && arg.kind() != "," {
                                        return self.extract_array_base(&arg, source);
                                    }
                                }
                            }
                        }
                    }
                    // Allocation functions create distinct objects
                    if matches!(
                        canonical,
                        "malloc" | "calloc" | "realloc" | "aligned_alloc" | "alloca"
                    ) {
                        return format!("alloc@{}", node.start_byte());
                    }
                }
                // Other calls: unknown origin — don't assign a base.
                // Assigning a unique base would cause every unknown-call pointer
                // to mismatch with everything else, producing massive FPs.
                String::new()
            }
            "compound_literal_expression" => {
                // Handle compound literals like (int[]){1, 2, 3}
                // Each compound literal creates a distinct object
                // Use byte position to make each one unique, even if they have identical content
                format!(
                    "{}@{}",
                    &source[node.start_byte()..node.end_byte()],
                    node.start_byte()
                )
            }
            "string_literal" => {
                // Handle string literals like "Hello" and "World"
                // Each string literal creates a distinct array object
                // Use byte position to make each one unique, even if they have identical text
                format!(
                    "{}@{}",
                    &source[node.start_byte()..node.end_byte()],
                    node.start_byte()
                )
            }
            "binary_expression" => {
                // Handle pointer arithmetic like arr + size or ptr - offset
                // The base array is determined by the left operand
                if let Some(left) = node.child_by_field_name("left") {
                    self.extract_array_base(&left, source)
                } else {
                    String::new()
                }
            }
            "pointer_expression" | "unary_expression" => {
                self.extract_base_from_address_or_deref(node, source)
            }
            "subscript_expression" => {
                // Handle array subscripts like arrays[0], arrays[1]
                // Use the full expression to distinguish between different sub-arrays
                // This is important for multidimensional arrays where arrays[0] and arrays[1]
                // are different arrays even though they share the same base
                source[node.start_byte()..node.end_byte()].to_string()
            }
            _ => String::new(),
        };
        result
    }

    /// Base of `&x`, `&x.y`, `&x[i]` or `*p`. tree-sitter spells both `&` and
    /// `*` as a `pointer_expression`, so the operator is read off child 0.
    ///
    /// Address-of yields the object itself, so an untracked name IS its own
    /// base; dereference follows the alias chain and yields nothing when that
    /// chain is unknown.
    fn extract_base_from_address_or_deref(&self, node: &Node, source: &str) -> String {
        let is_address_of = node
            .child(0)
            .is_some_and(|op| ast_utils::get_node_text(&op, source) == "&");
        let Some(argument) = node.child_by_field_name("argument") else {
            return String::new();
        };
        let text = |n: &Node| source[n.start_byte()..n.end_byte()].to_string();

        match argument.kind() {
            // &var: the variable itself IS the array (single-element).
            "identifier" if is_address_of => self.resolve_base(text(&argument)),
            // *ptr: the result points into whatever the pointer points to.
            "identifier" => self
                .variable_arrays
                .get(&text(&argument))
                .cloned()
                .unwrap_or_default(),
            // &struct.member: keep just the struct instance, so two members of
            // one struct compare equal (ARR36-C-EX1).
            "field_expression" => match argument.child_by_field_name("argument") {
                Some(base) => self.resolve_base(text(&base)),
                None => text(&argument),
            },
            // &matrix[i][j] is based on "matrix", not "matrix[i]".
            "subscript_expression" => self.extract_deepest_base(&argument, source),
            _ => String::new(),
        }
    }

    fn extract_deepest_base(&self, node: &Node, source: &str) -> String {
        // Recursively extract the deepest base array from nested subscript expressions
        // For matrix[i][j], this returns "matrix"
        // For matrix[i], this returns "matrix"
        match node.kind() {
            "subscript_expression" => {
                if let Some(array) = node.child_by_field_name("argument") {
                    self.extract_deepest_base(&array, source)
                } else {
                    String::new()
                }
            }
            "identifier" => {
                self.resolve_base(source[node.start_byte()..node.end_byte()].to_string())
            }
            _ => String::new(),
        }
    }

    /// Canonicalize a base spelled as a bare name.
    ///
    /// `variable_arrays` holds a base under whatever spelling first recorded
    /// it -- `param:work` for a parameter, `pPg->aData` for a local aliasing a
    /// member -- so every path that produces a base from an identifier has to
    /// resolve it the same way. When one does not, the rule compares a base
    /// against ITSELF under two spellings and reports a violation: `workend =
    /// &work[N]` recorded `work` where the parameter had recorded
    /// `param:work`, and `pEnd = &aData[n]` recorded `aData` where the
    /// declaration had recorded `pPg->aData` (task 770).
    fn resolve_base(&self, name: String) -> String {
        match self.variable_arrays.get(&name) {
            Some(base) => base.clone(),
            None => name,
        }
    }

    /// The storage OBJECT an argument expression hands to a callee, when this
    /// frame can name one: a declared array, the address of a non-pointer
    /// variable or struct member, a string or compound literal, or a fresh
    /// allocation.
    ///
    /// `None` for anything whose object this frame cannot name -- above all a
    /// bare pointer variable and `&ptr`. That is the point rather than a
    /// limitation: `f(&pos, end)` passes a cursor and its bound, and which
    /// buffer they walk is no more knowable in the caller than in the callee,
    /// so counting two pointer variables as two objects would restate one
    /// frame up exactly the assumption this is here to remove (task 753).
    fn argument_object_base(&self, node: &Node, source: &str) -> Option<String> {
        let text = |n: &Node| source[n.start_byte()..n.end_byte()].to_string();
        match node.kind() {
            "identifier" => {
                let name = text(node);
                self.array_objects.contains(&name).then_some(name)
            }
            // Each literal is its own object, as `extract_array_base` has it.
            "string_literal" | "compound_literal_expression" => {
                Some(format!("{}@{}", text(node), node.start_byte()))
            }
            "cast_expression" => {
                self.argument_object_base(&node.child_by_field_name("value")?, source)
            }
            // `arr + n` is still in `arr`.
            "binary_expression" => {
                self.argument_object_base(&node.child_by_field_name("left")?, source)
            }
            "call_expression" => self.allocation_object(node, source),
            "pointer_expression" | "unary_expression" => {
                let operator = node.child(0)?;
                if ast_utils::get_node_text(&operator, source) != "&" {
                    // `*p` names whatever p points to, which is the unknown.
                    return None;
                }
                self.object_of_lvalue(&node.child_by_field_name("argument")?, source)
            }
            _ => None,
        }
    }

    /// The object an lvalue names, for the `&lvalue` case.
    ///
    /// A pointer variable is excluded even though `&ptr` does name storage:
    /// what the callee then compares is `*param`, whose object is the
    /// pointer's target, not the pointer.
    fn object_of_lvalue(&self, node: &Node, source: &str) -> Option<String> {
        let text = |n: &Node| source[n.start_byte()..n.end_byte()].to_string();
        match node.kind() {
            "identifier" => {
                let name = text(node);
                let names_storage =
                    self.array_objects.contains(&name) || !self.pointer_vars.contains(&name);
                names_storage.then_some(name)
            }
            // Two members of one struct are two objects.
            "field_expression" => Some(text(node)),
            // `&matrix[i]` is in `matrix`.
            "subscript_expression" => {
                self.object_of_lvalue(&node.child_by_field_name("argument")?, source)
            }
            _ => None,
        }
    }

    /// A fresh allocation is its own object, so two allocation calls are two
    /// objects. Mirrors the allocation arm of `extract_array_base`.
    fn allocation_object(&self, node: &Node, source: &str) -> Option<String> {
        let func_node = node.child_by_field_name("function")?;
        let func_name = ast_utils::get_node_text(&func_node, source);
        let canonical = func_name.strip_prefix("os_").unwrap_or(func_name);
        matches!(
            canonical,
            "malloc" | "calloc" | "realloc" | "aligned_alloc" | "alloca"
        )
        .then(|| format!("alloc@{}", node.start_byte()))
    }

    fn get_pointer_info(&self, node: &Node, source: &str) -> Option<String> {
        match node.kind() {
            "identifier" => {
                let var_name = source[node.start_byte()..node.end_byte()].to_string();
                self.variable_arrays.get(&var_name).cloned()
            }
            "cast_expression" => {
                // Handle cast expressions like (int *)ptr - unwrap to get the underlying value
                if let Some(value) = node.child_by_field_name("value") {
                    self.get_pointer_info(&value, source)
                } else {
                    None
                }
            }
            "pointer_expression" | "unary_expression" => {
                // Handle &variable and *ptr patterns
                let is_address_of = node
                    .child(0)
                    .is_some_and(|op| ast_utils::get_node_text(&op, source) == "&");
                if let Some(argument) = node.child_by_field_name("argument") {
                    match argument.kind() {
                        "identifier" => {
                            let var_name =
                                source[argument.start_byte()..argument.end_byte()].to_string();
                            if is_address_of {
                                // &var: use tracked base or the variable name itself
                                Some(
                                    self.variable_arrays
                                        .get(&var_name)
                                        .cloned()
                                        .unwrap_or(var_name),
                                )
                            } else {
                                // *ptr: follow alias chain
                                self.variable_arrays.get(&var_name).cloned()
                            }
                        }
                        "field_expression" => {
                            let field_path =
                                source[argument.start_byte()..argument.end_byte()].to_string();
                            if is_address_of {
                                Some(
                                    self.variable_arrays
                                        .get(&field_path)
                                        .cloned()
                                        .unwrap_or(field_path),
                                )
                            } else {
                                self.variable_arrays.get(&field_path).cloned()
                            }
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            }
            "field_expression" => {
                // Handle struct.member or union.member access
                // Only return info if explicitly tracked — don't assume all field
                // expressions are pointers. Untracked fields (integers, etc.)
                // should return None to avoid flagging scalar comparisons.
                let var_name = source[node.start_byte()..node.end_byte()].to_string();
                self.variable_arrays.get(&var_name).cloned()
            }
            _ => None,
        }
    }
}

fn get_operator(node: &Node, source: &str) -> Option<String> {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            let text = source[child.start_byte()..child.end_byte()].to_string();
            if matches!(text.as_str(), "-" | "<" | "<=" | ">" | ">=") {
                return Some(text);
            }
        }
    }
    None
}
