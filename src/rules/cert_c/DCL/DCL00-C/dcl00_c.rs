use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use tree_sitter::Node;

pub struct Dcl00C;

impl CertRule for Dcl00C {
    fn rule_id(&self) -> &'static str {
        "DCL00-C"
    }

    fn description(&self) -> &'static str {
        "Const-qualify immutable objects"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "DCL00-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check init_declarators for variables that should be const
        if node.kind() == "init_declarator" {
            if let Some(declarator) = node.child_by_field_name("declarator") {
                if let Some(value) = node.child_by_field_name("value") {
                    if let Some(parent_decl) = find_parent_declaration(node) {
                        // Skip variables declared in for-loop init clauses — these are
                        // loop counters modified by the update expression (++i, etc.)
                        if is_in_for_loop_init(&parent_decl) {
                            return violations;
                        }
                        // Skip if already const-qualified
                        if !has_const_qualifier(&parent_decl, source) {
                            let var_name =
                                ast_utils::get_identifier_from_declarator(&declarator, source);

                            // Check if this should be const based on various patterns,
                            // but only if the variable is not actually modified later in
                            // its enclosing scope (reassignment, compound-assign, ++/--,
                            // address-of, or member/element write).
                            if should_be_const(&parent_decl, &declarator, &value, &var_name, source)
                                && !is_modified_in_scope(&parent_decl, &var_name, source)
                            {
                                let start_point = parent_decl.start_position();
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::Medium,
                                    message: format!(
                                        "Variable '{}' is initialized but never modified, consider const-qualifying it",
                                        var_name
                                    ),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some(format!("Add 'const' qualifier: const {} = ...", var_name)),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }
        }

        // Recursively check child nodes
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                violations.extend(self.check(&child, source));
            }
        }

        violations
    }
}

fn find_parent_declaration<'a>(node: &'a Node<'a>) -> Option<Node<'a>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "declaration" {
            return Some(parent);
        }
        current = parent.parent();
    }
    None
}

/// Check if a declaration is inside a for-loop's initializer clause.
/// Variables declared in `for (int i = 0; ...)` are loop counters that
/// are modified by the update expression — not candidates for const.
fn is_in_for_loop_init(decl_node: &Node) -> bool {
    if let Some(parent) = decl_node.parent() {
        if parent.kind() == "for_statement" {
            // Check if this declaration is the initializer field
            if let Some(init) = parent.child_by_field_name("initializer") {
                return init.id() == decl_node.id();
            }
        }
    }
    false
}

fn has_const_qualifier(node: &Node, source: &str) -> bool {
    let text = &source[node.start_byte()..node.end_byte()];
    text.contains("const")
}

fn should_be_const(
    decl_node: &Node,
    declarator_node: &Node,
    value_node: &Node,
    var_name: &str,
    source: &str,
) -> bool {
    let value_text = &source[value_node.start_byte()..value_node.end_byte()];
    let decl_text = &source[decl_node.start_byte()..decl_node.end_byte()];
    let var_lower = var_name.to_lowercase();

    // Check if this is a char array or pointer type
    let is_char_type = decl_text.contains("char");
    let is_array = declarator_node.kind() == "array_declarator";
    let is_pointer = is_pointer_declarator(declarator_node);
    let has_string_literal = value_text.starts_with('"') && value_text.ends_with('"');
    let has_brace_init = value_text.contains('{') && value_text.contains('}');

    // Exclude temporary/working variables that are likely to be modified
    let excluded_prefixes = ["current_", "temp_", "tmp_", "buffer_", "buf_", "work_"];
    if excluded_prefixes
        .iter()
        .any(|prefix| var_lower.starts_with(prefix))
    {
        return false;
    }

    // Pattern 1: Char arrays with string literals (HIGH CONFIDENCE)
    // Example: char config_dir[] = "/etc";
    if is_char_type && is_array && has_string_literal {
        return true;
    }

    // Pattern 2: Char pointers with string literals (HIGH CONFIDENCE)
    // Example: char *str = "literal"; (should be: const char *str)
    if is_char_type && is_pointer && has_string_literal {
        return true;
    }

    // Pattern 3: Function pointer arrays (HIGH CONFIDENCE)
    // Example: int (*operations[])(int, int) = {add, subtract, ...};
    if is_array && has_brace_init && decl_text.contains("(*") {
        return true;
    }

    // Pattern 4: Arrays with brace initializers and semantic naming
    // Only flag arrays that have meaningful constant-like names
    // Exclude generic working data names
    if is_array && has_brace_init {
        // Exclude generic/working data names
        let excluded_patterns = [
            "fibonacci",
            "test",
            "temp",
            "tmp",
            "buffer",
            "buf",
            "_array",
            "_data",
            "sort",
            "work",
            "example",
            "demo",
        ];

        let is_excluded = excluded_patterns
            .iter()
            .any(|pattern| var_lower.contains(pattern));

        if !is_excluded {
            // Include arrays with semantic names indicating lookup tables or constants
            let semantic_patterns = [
                "days",
                "month",
                "prime",
                "color",
                "command",
                "lookup",
                "table",
                "digit",
                "palette",
                "rgb",
                "hex",
                "state",
                "operation",
                "function",
                "menu",
            ];

            if semantic_patterns
                .iter()
                .any(|pattern| var_lower.contains(pattern))
            {
                return true;
            }
        }
    }

    // Pattern 5: Simple int scalars with numeric literals and semantic naming
    // Example: int rows = 3; (used as loop limit)
    let is_int_type = decl_text.contains("int");
    let is_scalar = !is_array && !is_pointer;
    let is_numeric_literal = value_text
        .chars()
        .all(|c| c.is_numeric() || c == '-' || c == '+');

    if is_int_type && is_scalar && is_numeric_literal {
        // Exclude counter/accumulator variables that are typically modified
        let counter_patterns = ["count", "counter", "index", "step", "iter"];
        if counter_patterns
            .iter()
            .any(|pattern| var_lower.contains(pattern))
        {
            return false;
        }

        // Only flag if the variable has a semantic name suggesting it's a BOUND/LIMIT
        let scalar_constant_patterns = [
            "rows", "cols", "columns", "_size", "limit", "bound", "width", "height", "depth",
            "num_", "start_", "end_", "batch_",
        ];

        if scalar_constant_patterns
            .iter()
            .any(|pattern| var_lower.contains(pattern))
        {
            return true;
        }
    }

    // Pattern 6: Well-known mathematical and scientific constant names
    let math_physics_constants = [
        "pi",
        "tau",
        "euler",
        "e", // Mathematical constants
        "gravity",
        "g",
        "speed_of_light",
        "c",
        "planck",
        "h", // Physics constants
        "avogadro",
        "boltzmann",
        "gas_constant",
        "r", // Chemistry/thermodynamics
        "epsilon",
        "mu",
        "sigma", // Greek letter constants
    ];

    for constant in &math_physics_constants {
        if var_lower == *constant || var_lower.ends_with(&format!("_{}", constant)) {
            return true;
        }
    }

    // Pattern 7: Conversion factors and rates
    let conversion_patterns = [
        "_per_", "_to_", "_rate", "_factor", "_ratio", "meters_", "kg_", "pounds_", "miles_",
        "feet_",
    ];

    for pattern in &conversion_patterns {
        if var_lower.contains(pattern) {
            return true;
        }
    }

    // Pattern 8: ALL_CAPS naming (indicates constant intent)
    if var_name.len() > 1 {
        let all_caps = var_name
            .chars()
            .all(|c| c.is_uppercase() || c == '_' || c.is_numeric());
        let has_alpha = var_name.chars().any(|c| c.is_alphabetic());
        if all_caps && has_alpha {
            return true;
        }
    }

    // Pattern 9: kConstant naming convention
    if var_name.starts_with("k") && var_name.len() > 1 {
        if let Some(second_char) = var_name.chars().nth(1) {
            if second_char.is_uppercase() {
                return true;
            }
        }
    }

    // Pattern 10: Common constant suffixes
    let constant_suffixes = [
        "_MAX",
        "_MIN",
        "_SIZE",
        "_COUNT",
        "_LIMIT",
        "_CAPACITY",
        "_LENGTH",
        "_WIDTH",
        "_HEIGHT",
        "_TIMEOUT",
        "_INTERVAL",
        "_THRESHOLD",
    ];

    for suffix in &constant_suffixes {
        if var_name.contains(suffix) {
            return true;
        }
    }

    // Pattern 11: File and path related names with string literals
    // Only flag if it's also a char array/pointer with a string literal
    if is_char_type && has_string_literal {
        let path_file_patterns = [
            "_dir",
            "_path",
            "_folder",
            "_directory",
            "_extension",
            "_ext",
            "_prefix",
            "_suffix",
            "_url",
            "_uri",
            "_pattern",
            "_format",
            "_template",
        ];

        for pattern in &path_file_patterns {
            if var_lower.contains(pattern) {
                return true;
            }
        }

        // Also check for common file-related words
        if var_lower.contains("file") && has_string_literal {
            // Only if it's a string literal assignment, not a FILE* pointer
            return true;
        }
    }

    // Pattern 12: Struct initializations with semantic names
    // Example: struct Point origin = {0.0, 0.0, 0.0};
    if has_brace_init && decl_text.contains("struct") {
        let struct_constant_names = [
            "origin",
            "config",
            "configuration",
            "default",
            "initial",
            "settings",
            "options",
            "params",
            "parameters",
        ];

        for name in &struct_constant_names {
            if var_lower.contains(name) {
                return true;
            }
        }
    }

    false
}

/// Returns true if `var_name` is mutated anywhere in its enclosing scope:
/// reassignment, compound assignment, `++`/`--`, having its address taken,
/// or a member/element write (`v.x =`, `v->x =`, `v[i] =`, `*v =`). Used to
/// suppress a const recommendation for a variable that is in fact modified
/// later — including in if/else branches, loop bodies, and member writes that
/// the name-heuristic patterns above cannot see. The declaration's own
/// initializer is not an `assignment_expression`, so it is never counted.
fn is_modified_in_scope(decl_node: &Node, var_name: &str, source: &str) -> bool {
    let scope = match enclosing_scope(decl_node) {
        Some(s) => s,
        None => return false,
    };
    scope_has_mutation(&scope, var_name, source)
}

/// Walk up to the innermost enclosing block (`compound_statement`) for a local
/// or the `translation_unit` for a file-scope variable. When neither is found
/// — e.g. a malformed file (unbalanced `extern "C"` brace) parses with an
/// `ERROR` root instead of a `translation_unit` — fall back to the topmost
/// ancestor so the mutation scan still covers the whole file.
fn enclosing_scope<'a>(node: &'a Node<'a>) -> Option<Node<'a>> {
    let mut current = node.parent();
    let mut topmost = None;
    while let Some(n) = current {
        if n.kind() == "compound_statement" || n.kind() == "translation_unit" {
            return Some(n);
        }
        topmost = Some(n);
        current = n.parent();
    }
    topmost
}

fn scope_has_mutation(node: &Node, var_name: &str, source: &str) -> bool {
    match node.kind() {
        // Covers `=` and all compound assignments (`+=`, `<<=`, ...).
        "assignment_expression" => {
            if let Some(left) = node.child_by_field_name("left") {
                if lvalue_base_is(&left, var_name, source) {
                    return true;
                }
            }
        }
        "update_expression" => {
            if let Some(arg) = node.child_by_field_name("argument") {
                if lvalue_base_is(&arg, var_name, source) {
                    return true;
                }
            }
        }
        // Address-of (`&var`): the variable may be mutated through the pointer.
        "pointer_expression" => {
            if let Some(op) = node.child_by_field_name("operator") {
                if &source[op.start_byte()..op.end_byte()] == "&" {
                    if let Some(arg) = node.child_by_field_name("argument") {
                        if lvalue_base_is(&arg, var_name, source) {
                            return true;
                        }
                    }
                }
            }
        }
        _ => {}
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if scope_has_mutation(&child, var_name, source) {
                return true;
            }
        }
    }
    false
}

/// True if the base object of an lvalue is `var_name`, descending through
/// member access (`v.x`, `v->x`), subscripts (`v[i]`), pointer deref (`*v`),
/// and parentheses to the underlying identifier.
fn lvalue_base_is(node: &Node, var_name: &str, source: &str) -> bool {
    match node.kind() {
        "identifier" => &source[node.start_byte()..node.end_byte()] == var_name,
        "field_expression" | "subscript_expression" | "pointer_expression" => node
            .child_by_field_name("argument")
            .map(|a| lvalue_base_is(&a, var_name, source))
            .unwrap_or(false),
        "parenthesized_expression" => (0..node.child_count())
            .filter_map(|i| node.child(i))
            .any(|c| lvalue_base_is(&c, var_name, source)),
        _ => false,
    }
}

fn is_pointer_declarator(node: &Node) -> bool {
    node.kind() == "pointer_declarator" || node.to_sexp().contains("pointer_declarator")
}
