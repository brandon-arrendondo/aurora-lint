use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Dcl13C;

impl CertRule for Dcl13C {
    fn rule_id(&self) -> &'static str {
        "DCL13-C"
    }

    fn description(&self) -> &'static str {
        "Declare function parameters that are pointers to values not changed by the function as const"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "DCL13-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check all function definitions and declarations
        for found in
            query::find_descendants_of_kinds(*node, &["function_definition", "declaration"])
        {
            match found.kind() {
                "function_definition" => {
                    check_function_definition(&found, source, &mut violations, self.rule_id());
                }
                "declaration" => {
                    // Check for function declarations (prototypes)
                    check_function_declaration(&found, source, &mut violations, self.rule_id());
                }
                _ => {}
            }
        }

        violations
    }
}

/// Get the name of the function being defined
fn get_function_name(func_node: &Node, source: &str) -> Option<String> {
    for i in 0..func_node.child_count() {
        if let Some(child) = func_node.child(i) {
            if let Some(name) = find_name_in_declarator(&child, source) {
                return Some(name);
            }
        }
    }
    None
}

fn find_name_in_declarator(node: &Node, source: &str) -> Option<String> {
    if node.kind() == "function_declarator" {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "identifier" {
                    return Some(ast_utils::get_node_text(&child, source).to_string());
                }
                if child.kind() == "pointer_declarator" {
                    if let Some(name) = find_name_in_declarator(&child, source) {
                        return Some(name);
                    }
                }
            }
        }
    } else if node.kind() == "pointer_declarator" {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(name) = find_name_in_declarator(&child, source) {
                    return Some(name);
                }
            }
        }
    }
    None
}

/// Check a function definition for const-correctness of pointer parameters
fn check_function_definition(
    func_node: &Node,
    source: &str,
    violations: &mut Vec<RuleViolation>,
    rule_id: &str,
) {
    // Skip main() — its signature (int argc, char *argv[]) is mandated by the C standard;
    // requiring const on argv is incorrect and generates FPs on every Juliet test file.
    if get_function_name(func_node, source).as_deref() == Some("main") {
        return;
    }

    // Extract function parameters with their const-qualification status
    let params = extract_function_parameters(func_node, source);

    // Find the function body
    let body = find_compound_statement(func_node);

    // For each pointer parameter, check if it's modified in the function body
    for (param_name, is_const, is_pointer, line, col) in params {
        if !is_pointer {
            continue; // Only check pointer parameters
        }

        // DCL13-C: "Declare function parameters that are pointers to values
        // not changed by the function as const"
        // If already const-qualified, there's nothing for DCL13-C to flag.
        if is_const {
            continue;
        }

        // Check if this parameter is modified in the function body
        // Also check through local pointer aliases (e.g., `T *cur = param;`)
        let is_modified = if let Some(body_node) = body {
            if is_pointer_param_modified(&body_node, &param_name, source) {
                true
            } else {
                let aliases = collect_pointer_aliases(&body_node, &param_name, source);
                aliases
                    .iter()
                    .any(|alias| is_pointer_param_modified(&body_node, alias, source))
            }
        } else {
            false // No body, assume not modified
        };

        if !is_modified {
            // Non-const pointer parameter that is never modified — should be const.
            violations.push(RuleViolation {
                rule_id: rule_id.to_string(),
                severity: Severity::Low,
                message: format!(
                    "Pointer parameter '{}' is not modified and should be declared const",
                    param_name
                ),
                file_path: String::new(),
                line,
                column: col,
                suggestion: Some(format!(
                    "Declare parameter as 'const <type> *{}'",
                    param_name
                )),
                ..Default::default()
            });
        }
    }
}

/// Check a function declaration for const-correctness of pointer parameters
fn check_function_declaration(
    decl_node: &Node,
    source: &str,
    violations: &mut Vec<RuleViolation>,
    rule_id: &str,
) {
    // Look for function declarators in the declaration
    for i in 0..decl_node.child_count() {
        if let Some(child) = decl_node.child(i) {
            if child.kind() == "function_declarator" || is_function_declarator(&child) {
                // For function declarations (no body), we can only check basic patterns
                // We'll flag non-const pointer parameters as potential issues
                let params = extract_params_from_declarator(&child, source);

                for (param_name, is_const, is_pointer, line, col) in params {
                    if is_pointer && !is_const && !param_name.is_empty() {
                        // Only flag if it's a clear case where const would be appropriate
                        // (e.g., second parameter of strcat-like functions)
                        // For declarations without bodies, we can't analyze usage,
                        // so we'll be conservative and only flag obvious cases

                        // Check if this looks like a read-only parameter by naming convention
                        // (src, source, input, etc.) or position (second param in string functions)
                        if is_likely_readonly_param(&param_name) {
                            violations.push(RuleViolation {
                                rule_id: rule_id.to_string(),
                                severity: Severity::Low,
                                message: format!(
                                    "Pointer parameter '{}' should likely be declared const",
                                    param_name
                                ),
                                file_path: String::new(),
                                line,
                                column: col,
                                suggestion: Some(format!(
                                    "Consider declaring parameter as 'const <type> *{}'",
                                    param_name
                                )),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Check if a parameter name suggests it should be read-only
fn is_likely_readonly_param(name: &str) -> bool {
    let lowercase = name.to_lowercase();
    lowercase.starts_with("src")
        || lowercase.starts_with("source")
        || lowercase.starts_with("input")
        || lowercase.starts_with("in_")
        || lowercase.contains("read")
        || lowercase == "s2" // Conventional second string parameter name (e.g., s2 in strcat/strcmp)
}

/// Check if a node is a function declarator (recursively checking pointer/array decorators)
fn is_function_declarator(node: &Node) -> bool {
    if node.kind() == "function_declarator" {
        return true;
    }

    // Check children for nested declarators
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if is_function_declarator(&child) {
                return true;
            }
        }
    }

    false
}

/// Extract parameters from a function declarator
fn extract_params_from_declarator(
    declarator: &Node,
    source: &str,
) -> Vec<(String, bool, bool, usize, usize)> {
    let mut params = Vec::new();

    // Find parameter_list
    if let Some(param_list) = find_parameter_list(declarator) {
        for i in 0..param_list.child_count() {
            if let Some(param) = param_list.child(i) {
                if param.kind() == "parameter_declaration" {
                    if let Some((name, is_const, is_pointer, line, col)) =
                        analyze_parameter(&param, source)
                    {
                        params.push((name, is_const, is_pointer, line, col));
                    }
                }
            }
        }
    }

    params
}

/// Find parameter_list in a function declarator
fn find_parameter_list<'a>(declarator: &Node<'a>) -> Option<Node<'a>> {
    for i in 0..declarator.child_count() {
        if let Some(child) = declarator.child(i) {
            if child.kind() == "parameter_list" {
                return Some(child);
            }
            // Recursively search in nested declarators
            if let Some(found) = find_parameter_list(&child) {
                return Some(found);
            }
        }
    }
    None
}

/// Functions known to NOT modify their pointer arguments.
/// If a pointer parameter is passed to a function NOT in this list,
/// we conservatively assume the function may modify the pointed-to data.
const READ_ONLY_FUNCTIONS: &[&str] = &[
    // C stdio - output (read format string and args)
    "printf", "fprintf", "vprintf", "vfprintf", "wprintf", "fwprintf", "puts", "fputs", "putchar",
    "fputc", "putc", // C stdio - file ops (don't modify pointer args)
    "ftell", "feof", "ferror", "fopen", // C string - read-only
    "strlen", "strcmp", "strncmp", "strchr", "strrchr", "strstr", "strpbrk", "strspn", "strcspn",
    "strerror", // C wide string - read-only
    "wcslen", "wcscmp", "wcsncmp", "wcschr", "wcsrchr", "wcsstr",
    // C memory - read-only
    "memcmp", "memchr",
    // C search/sort (bsearch reads the array; qsort modifies so NOT listed)
    "bsearch", // C string - duplication (reads source string)
    "strdup", "strndup", "wcsdup", // C conversion (first arg is read-only string)
    "atoi", "atol", "atof", "atoll", // C ctype
    "isalpha", "isdigit", "isalnum", "isspace", "isupper", "islower", "ispunct", "isprint",
    "iscntrl", "isxdigit", "isgraph", "toupper", "tolower", // C math
    "abs", "labs", "llabs", "fabs", "sqrt", "pow", "ceil", "floor", "log", "log10", "exp", "sin",
    "cos", "tan", // C assert / control flow
    "assert", "exit", "abort", "_exit", "_Exit", // POSIX - read-only for pointer args
    "write", "open", "close", "perror", "access", "stat", "lstat",
];

/// Check if a pointer parameter is modified in the function body
fn is_pointer_param_modified(body: &Node, param_name: &str, source: &str) -> bool {
    query::find_first_descendant(*body, |node| {
        // Check if this is an assignment where LHS writes through param
        if node.kind() == "assignment_expression" {
            if let Some(left) = node.child_by_field_name("left") {
                if is_write_through_param(&left, param_name, source) {
                    return true;
                }
            }
        }

        // Check for increment/decrement through param (e.g., (*p)++, p->field++)
        if node.kind() == "update_expression" {
            if let Some(argument) = node.child_by_field_name("argument") {
                if is_write_through_param(&argument, param_name, source) {
                    return true;
                }
            }
        }

        // Check if param is passed to a function that may modify it
        if node.kind() == "call_expression"
            && is_param_passed_to_modifying_call(&node, param_name, source)
        {
            return true;
        }

        false
    })
    .is_some()
}

/// Collect local pointer variables that are initialized from a parameter.
///
/// Detects patterns like `T *cur = param;` or `T *alias = (T *)param;`.
/// Returns the names of local aliases so modifications through them
/// can be attributed back to the original parameter.
fn collect_pointer_aliases(body: &Node, param_name: &str, source: &str) -> Vec<String> {
    let mut aliases = Vec::new();
    for node in query::find_descendants_of_kind(*body, "declaration") {
        // Look for init_declarator children with pointer declarator
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "init_declarator" {
                    // Check if the initializer value is the parameter
                    if let Some(value) = child.child_by_field_name("value") {
                        if arg_is_param(&value, param_name, source) {
                            // Extract the declared name from the declarator
                            if let Some(declarator) = child.child_by_field_name("declarator") {
                                if let Some(name) =
                                    find_identifier_in_declarator(&declarator, source)
                                {
                                    aliases.push(name);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    aliases
}

/// Extract the identifier name from a declarator node (handles pointer_declarator wrapping).
fn find_identifier_in_declarator(node: &Node, source: &str) -> Option<String> {
    if node.kind() == "identifier" {
        return Some(ast_utils::get_node_text(node, source).to_string());
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if let Some(name) = find_identifier_in_declarator(&child, source) {
                return Some(name);
            }
        }
    }
    None
}

/// Check if a node represents writing through a parameter (dereferencing the pointed-to data).
///
/// Handles: `*param`, `param->field`, `param[i]`, `param->field[i]`,
/// `param->field1->field2`, `(*param).field`, and nested combinations.
fn is_write_through_param(node: &Node, param_name: &str, source: &str) -> bool {
    match node.kind() {
        "pointer_expression" => {
            // *param
            if let Some(argument) = node.child_by_field_name("argument") {
                let text = ast_utils::get_node_text(&argument, source);
                if text == param_name {
                    return true;
                }
            }
        }
        "field_expression" => {
            // param->field or param->field1->field2
            if let Some(argument) = node.child_by_field_name("argument") {
                let text = ast_utils::get_node_text(&argument, source);
                if text == param_name {
                    return true;
                }
                // Nested: param->field1->field2, (*param).field, etc.
                return is_write_through_param(&argument, param_name, source);
            }
        }
        "subscript_expression" => {
            // param[i] or param->items[i]
            if let Some(argument) = node.child_by_field_name("argument") {
                let text = ast_utils::get_node_text(&argument, source);
                if text == param_name {
                    return true;
                }
                // Nested: param->items[i]
                return is_write_through_param(&argument, param_name, source);
            }
        }
        "parenthesized_expression" => {
            // (*param) — unwrap parens
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() != "(" && child.kind() != ")" {
                        return is_write_through_param(&child, param_name, source);
                    }
                }
            }
        }
        _ => {}
    }
    false
}

/// Check if an argument is `&(param->field)`, `&param[i]`, or similar address-of
/// expressions that take the address of the parameter's member data.
///
/// Passing `&(param->field)` to a non-read-only function means the callee can
/// modify `param->field`, so the struct pointed to by `param` is modified.
fn arg_addresses_param_member(node: &Node, param_name: &str, source: &str) -> bool {
    // tree-sitter C parses &expr as pointer_expression (same node kind as *expr)
    if node.kind() != "pointer_expression" {
        return false;
    }
    // Check for & operator (vs * dereference)
    if let Some(op_node) = node.child_by_field_name("operator") {
        if ast_utils::get_node_text(&op_node, source) != "&" {
            return false;
        }
    } else {
        return false;
    }
    // The operand of & should derive from param (e.g., param->field, param[i])
    if let Some(argument) = node.child_by_field_name("argument") {
        return expr_derives_from_param(&argument, param_name, source);
    }
    false
}

/// Check if an expression is rooted in a parameter (for address-of detection).
///
/// Matches: `param->field`, `param[i]`, `(*param).field`, `((param->field))`,
/// and nested combinations like `param->a->b`.
fn expr_derives_from_param(node: &Node, param_name: &str, source: &str) -> bool {
    match node.kind() {
        "field_expression" => {
            if let Some(argument) = node.child_by_field_name("argument") {
                let text = ast_utils::get_node_text(&argument, source);
                if text == param_name {
                    return true;
                }
                return expr_derives_from_param(&argument, param_name, source);
            }
            false
        }
        "subscript_expression" => {
            if let Some(argument) = node.child(0) {
                let text = ast_utils::get_node_text(&argument, source);
                if text == param_name {
                    return true;
                }
                return expr_derives_from_param(&argument, param_name, source);
            }
            false
        }
        "pointer_expression" => {
            if let Some(argument) = node.child_by_field_name("argument") {
                let text = ast_utils::get_node_text(&argument, source);
                if text == param_name {
                    return true;
                }
                return expr_derives_from_param(&argument, param_name, source);
            }
            false
        }
        "parenthesized_expression" => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() != "(" && child.kind() != ")" {
                        return expr_derives_from_param(&child, param_name, source);
                    }
                }
            }
            false
        }
        _ => false,
    }
}

/// Check if an argument expression is the parameter itself (directly or through a cast).
///
/// Only matches direct usage: `param`, `(void*)param`, `((param))`.
/// Does NOT match derived expressions like `param->field` or `param[i]`,
/// because passing a member's value to a function doesn't constitute
/// modification of the struct the parameter points to.
fn arg_is_param(node: &Node, param_name: &str, source: &str) -> bool {
    match node.kind() {
        "identifier" => ast_utils::get_node_text(node, source) == param_name,
        "cast_expression" => {
            // (void*)param
            if let Some(value) = node.child_by_field_name("value") {
                return arg_is_param(&value, param_name, source);
            }
            false
        }
        "parenthesized_expression" => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() != "(" && child.kind() != ")" {
                        return arg_is_param(&child, param_name, source);
                    }
                }
            }
            false
        }
        _ => false,
    }
}

/// Check if a pointer parameter is passed to a function that may modify it.
///
/// Returns true if the param (or an expression rooted in it) appears as an
/// argument to a function call, and that function is NOT in the read-only
/// whitelist. This conservatively assumes unknown functions may write through
/// their pointer arguments.
fn is_param_passed_to_modifying_call(call_node: &Node, param_name: &str, source: &str) -> bool {
    let args = match call_node.child_by_field_name("arguments") {
        Some(a) => a,
        None => return false,
    };

    // Check if param appears as any argument (direct, cast, or address-of-member)
    let mut param_is_arg = false;
    for i in 0..args.child_count() {
        if let Some(arg) = args.child(i) {
            if arg.kind() == "," || arg.kind() == "(" || arg.kind() == ")" {
                continue;
            }
            if arg_is_param(&arg, param_name, source)
                || arg_addresses_param_member(&arg, param_name, source)
            {
                param_is_arg = true;
                break;
            }
        }
    }

    if !param_is_arg {
        return false;
    }

    // Get function name — if it's a known read-only function, not a modification
    if let Some(func) = call_node.child_by_field_name("function") {
        let func_name = ast_utils::get_node_text(&func, source);
        if READ_ONLY_FUNCTIONS.contains(&func_name) {
            return false;
        }
    }

    // Unknown or non-read-only function with our param as argument → assume modification
    true
}

/// Extract function parameters with const-qualification and pointer status
///
/// Returns: Vec<(parameter_name, is_const, is_pointer, line_number, column_number)>
fn extract_function_parameters(
    func_node: &Node,
    source: &str,
) -> Vec<(String, bool, bool, usize, usize)> {
    let mut parameters = Vec::new();

    // Find the function_declarator
    for i in 0..func_node.child_count() {
        if let Some(child) = func_node.child(i) {
            if child.kind() == "function_declarator"
                || is_pointer_or_array_with_func_declarator(&child)
            {
                if let Some(param_list) = find_parameter_list(&child) {
                    // Extract each parameter
                    for j in 0..param_list.child_count() {
                        if let Some(param) = param_list.child(j) {
                            if param.kind() == "parameter_declaration" {
                                if let Some((name, is_const, is_pointer, line, col)) =
                                    analyze_parameter(&param, source)
                                {
                                    parameters.push((name, is_const, is_pointer, line, col));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    parameters
}

/// Check if node is a pointer/array declarator that contains a function declarator
fn is_pointer_or_array_with_func_declarator(node: &Node) -> bool {
    if node.kind() == "pointer_declarator" || node.kind() == "array_declarator" {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "function_declarator"
                    || is_pointer_or_array_with_func_declarator(&child)
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Analyze a parameter declaration to extract name, const status, and pointer status
///
/// Returns: Some((name, is_const, is_pointer, line, col)) or None
fn analyze_parameter(param: &Node, source: &str) -> Option<(String, bool, bool, usize, usize)> {
    let mut is_const = false;
    let mut is_pointer = false;
    let mut param_name = String::new();
    let mut line = 0;
    let mut col = 0;

    // Check for type qualifiers (const)
    for i in 0..param.child_count() {
        if let Some(child) = param.child(i) {
            match child.kind() {
                "type_qualifier" => {
                    let text = ast_utils::get_node_text(&child, source);
                    if text == "const" {
                        is_const = true;
                    }
                }
                "pointer_declarator" => {
                    is_pointer = true;
                    param_name = ast_utils::get_identifier_from_declarator(&child, source);
                    if !param_name.is_empty() {
                        let pos = child.start_position();
                        line = pos.row + 1;
                        col = pos.column + 1;
                    }
                }
                "array_declarator" => {
                    is_pointer = true; // Arrays decay to pointers in function parameters
                    param_name = ast_utils::get_identifier_from_declarator(&child, source);
                    if !param_name.is_empty() {
                        let pos = child.start_position();
                        line = pos.row + 1;
                        col = pos.column + 1;
                    }
                }
                "identifier"
                    // Direct identifier (might be non-pointer parameter)
                    if param_name.is_empty() => {
                        param_name = ast_utils::get_node_text(&child, source).to_string();
                        let pos = child.start_position();
                        line = pos.row + 1;
                        col = pos.column + 1;
                    }
                "primitive_type" | "type_identifier" | "struct_specifier" | "union_specifier"
                | "enum_specifier"
                    // Type specifier - check if followed by pointer
                    if i + 1 < param.child_count() => {
                        if let Some(next) = param.child(i + 1) {
                            if next.kind() == "*" || next.kind() == "abstract_pointer_declarator" {
                                is_pointer = true;
                            }
                        }
                    }
                _ => {}
            }
        }
    }

    if !param_name.is_empty() {
        Some((param_name, is_const, is_pointer, line, col))
    } else {
        None
    }
}

/// Find the compound_statement (body) of a function
fn find_compound_statement<'a>(func_node: &Node<'a>) -> Option<Node<'a>> {
    for i in 0..func_node.child_count() {
        if let Some(child) = func_node.child(i) {
            if child.kind() == "compound_statement" {
                return Some(child);
            }
        }
    }
    None
}
