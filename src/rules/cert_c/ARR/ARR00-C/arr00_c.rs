//! ARR00-C: Understand how arrays work
//!
//! This rule checks for common misunderstandings about how arrays work in C:
//! - Direct array assignment (arrays are not assignable)
//! - Array comparison with == or != (compares addresses, not contents)
//! - sizeof() misuse on array parameters (arrays decay to pointers)
//! - Variable Length Arrays (VLAs) with zero, negative, or unvalidated sizes
//! - Use of gets() which has no bounds checking mechanism and is always unsafe
//! - Using unvalidated user input as loop bounds for array access
//! - Using uninitialized variables as loop bounds for array access
//! - Pointer arithmetic that obviously exceeds array bounds
//!
//! Note: Other unsafe functions (strcpy, etc.) are better checked by ARR38-C

use super::super::{CertRule, RuleViolation};
use crate::analyze::const_eval::{collect_macro_constants, try_evaluate_expr, MacroConstantMap};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{
    find_containing_function, get_function_parameters, is_array_parameter_type,
    is_function_parameter, is_inside_loop, is_write_context,
};
use crate::utility::cert_c::size_analysis::{
    find_allocation_size, find_element_size, find_string_literal_length,
};
use crate::utility::cert_c::variable_analysis::{
    has_bounds_validation, has_validation_before_loop, is_uninitialized_variable,
    is_user_input_variable,
};
use tree_sitter::Node;

pub struct Arr00C;

impl CertRule for Arr00C {
    fn rule_id(&self) -> &'static str {
        "ARR00-C"
    }

    fn description(&self) -> &'static str {
        "Understand how arrays are used"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "ARR00-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Macro/const-expr table for resolving array dimension expressions
        // (e.g. `arr[2*SPLINE_SEGMENT_DIVISIONS + 2]`). Built once per file.
        let macros = collect_macro_constants(node, source);

        // Iterative pre-order traversal: deeply nested ASTs (e.g. files with
        // thousands of chained `else if` branches) overflow the stack if each
        // node level adds a call frame.
        let mut stack = vec![*node];
        while let Some(current) = stack.pop() {
            let node = &current;
            match node.kind() {
                "assignment_expression" => {
                    // Check for direct array assignment (arr1 = arr2)
                    if let Some(violation) = check_array_assignment(node, source) {
                        violations.push(violation);
                    }
                }
                "sizeof_expression" => {
                    // Check for sizeof misuse with array parameters
                    if let Some(violation) = check_sizeof_misuse(node, source) {
                        violations.push(violation);
                    }
                }
                "binary_expression" => {
                    // Check for array comparison with == or !=
                    if let Some(violation) = check_array_comparison(node, source) {
                        violations.push(violation);
                    }
                    // Also check for pointer arithmetic that exceeds bounds
                    if let Some(violation) = check_pointer_arithmetic(node, source) {
                        violations.push(violation);
                    }
                    // Check for pointer subtraction between different arrays
                    if let Some(violation) = check_pointer_subtraction(node, source) {
                        violations.push(violation);
                    }
                }
                "declaration" => {
                    // Check for VLA with zero or invalid size
                    if let Some(violation) = check_vla_declaration(node, source) {
                        violations.push(violation);
                    }
                }
                "call_expression" => {
                    // Check for dangerous functions like gets(), strcpy(), etc.
                    if let Some(violation) = check_dangerous_functions(node, source) {
                        violations.push(violation);
                    }
                    // Check for obviously wrong string operations (strcat/strcpy with literal too large)
                    if let Some(violation) = check_obvious_string_overflow(node, source) {
                        violations.push(violation);
                    }
                    // Check for memcpy/memmove with wrong size
                    if let Some(violation) = check_memcpy_size_mismatch(node, source) {
                        violations.push(violation);
                    }
                    // Check for memory operations with size exceeding buffer
                    if let Some(violation) = check_memory_operation_overflow(node, source) {
                        violations.push(violation);
                    }
                }
                "for_statement" => {
                    // Check for loops exceeding malloc/realloc allocation size
                    if let Some(violation) = check_loop_exceeds_allocation(node, source) {
                        violations.push(violation);
                    }
                    // Check for loops with bounds that exceed array size
                    if let Some(violation) = check_loop_bound_exceeds_array(node, source) {
                        violations.push(violation);
                    }
                    // Check for loops with unvalidated bounds accessing arrays
                    if let Some(violation) = check_loop_array_access(node, source) {
                        violations.push(violation);
                    }
                }
                "return_statement" => {
                    // Check for returning pointer to local array
                    if let Some(violation) = check_return_local_array(node, source) {
                        violations.push(violation);
                    }
                }
                "subscript_expression" => {
                    // Check for comma operator in subscript (incorrect 2D access)
                    if let Some(violation) = check_comma_in_subscript(node, source) {
                        violations.push(violation);
                    }
                    // Check for reading from uninitialized array
                    if let Some(violation) = check_uninitialized_array_read(node, source) {
                        violations.push(violation);
                    }
                    // Check for array access after free
                    if let Some(violation) = check_use_after_free(node, source) {
                        violations.push(violation);
                    }
                    // Check for array access with constant out-of-bounds index
                    if let Some(violation) = check_constant_out_of_bounds(node, source, &macros) {
                        violations.push(violation);
                    }
                    // Check for array access with unvalidated index
                    if let Some(violation) = check_subscript_bounds(node, source) {
                        violations.push(violation);
                    }
                    // Check for array access with boundary value index
                    if let Some(violation) = check_boundary_value_index(node, source) {
                        violations.push(violation);
                    }
                }
                _ => {}
            }

            // Push children in reverse so they are visited in source order
            for i in (0..node.child_count()).rev() {
                if let Some(child) = node.child(i) {
                    stack.push(child);
                }
            }
        }

        violations
    }
}

// ============================================================================
// Core Rule Checks
// ============================================================================

fn check_array_assignment(node: &Node, source: &str) -> Option<RuleViolation> {
    // Only flag plain '=' assignments, not compound assignments (+=, -=, etc.)
    // which are valid pointer arithmetic operations.
    if let Some(op) = node.child_by_field_name("operator") {
        let op_text = &source[op.start_byte()..op.end_byte()];
        if op_text != "=" {
            return None;
        }
    }

    // Get left and right operands of assignment
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;

    // Check if left side is an array identifier (not a subscript)
    if is_array_identifier(&left, source) && !is_subscript(&left) {
        // Check if right side is also an array identifier
        if is_array_identifier(&right, source) {
            let start_point = node.start_position();
            let left_text = &source[left.start_byte()..left.end_byte()];
            let right_text = &source[right.start_byte()..right.end_byte()];

            return Some(RuleViolation {
                rule_id: "ARR00-C".to_string(),
                severity: Severity::High,
                message: format!(
                    "Cannot directly assign arrays: '{}' = '{}'. Arrays are not assignable in C.",
                    left_text, right_text
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some("Use memcpy() or a loop to copy array elements".to_string()),
                ..Default::default()
            });
        }
    }

    None
}

fn check_sizeof_misuse(node: &Node, source: &str) -> Option<RuleViolation> {
    // For sizeof expressions, we need to look at the second child (index 1) which is typically the parenthesized expression
    if node.child_count() >= 2 {
        if let Some(arg_expr) = node.child(1) {
            if arg_expr.kind() == "parenthesized_expression" {
                // Look inside the parentheses for an identifier
                for i in 0..arg_expr.child_count() {
                    if let Some(child) = arg_expr.child(i) {
                        if child.kind() == "identifier" {
                            return check_if_array_parameter(&child, node, source);
                        }
                    }
                }
            } else if arg_expr.kind() == "identifier" {
                // Direct identifier without parentheses
                return check_if_array_parameter(&arg_expr, node, source);
            }
        }
    }

    None
}

fn check_if_array_parameter(
    identifier_node: &Node,
    sizeof_node: &Node,
    source: &str,
) -> Option<RuleViolation> {
    let identifier_name = &source[identifier_node.start_byte()..identifier_node.end_byte()];

    // Find the containing function
    let function_def = find_containing_function(identifier_node)?;

    // Get the function's parameters
    let parameters = get_function_parameters(&function_def, source)?;

    // Check if this identifier is a parameter declared as an array
    for (param_name, param_type) in parameters {
        if param_name == identifier_name && is_array_parameter_type(&param_type) {
            let start_point = sizeof_node.start_position();
            return Some(RuleViolation {
                rule_id: "ARR00-C".to_string(),
                severity: Severity::Medium,
                message: format!(
                    "Misuse of sizeof() on array parameter '{}'. Array parameters decay to pointers, sizeof will return pointer size not array size.",
                    identifier_name
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some("Pass array size as a separate parameter or use a different method to track array size".to_string()),
            ..Default::default()
            });
        }
    }

    None
}

fn check_vla_declaration(node: &Node, source: &str) -> Option<RuleViolation> {
    // Look for array_declarator in the declaration
    let mut declarator = None;
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "array_declarator" {
                declarator = Some(child);
                break;
            } else if child.kind() == "init_declarator" {
                // Check inside init_declarator for array_declarator
                for j in 0..child.child_count() {
                    if let Some(inner) = child.child(j) {
                        if inner.kind() == "array_declarator" {
                            declarator = Some(inner);
                            break;
                        }
                    }
                }
            }
        }
    }

    let declarator = declarator?;

    // Get the size expression from the array declarator
    // array_declarator has structure: identifier [ size ]
    let mut size_node = None;
    let mut found_open_bracket = false;
    for i in 0..declarator.child_count() {
        if let Some(child) = declarator.child(i) {
            if child.kind() == "[" {
                found_open_bracket = true;
                continue;
            }
            // After '[', the next non-']' node is the size
            if found_open_bracket && child.kind() != "]" {
                size_node = Some(child);
                break;
            }
        }
    }

    let size_node = size_node?;
    let size_text = &source[size_node.start_byte()..size_node.end_byte()];

    // Check if size is a variable (VLA) - not a number literal
    let is_vla = size_node.kind() == "identifier"
        || size_node.kind() == "call_expression"
        || size_node.kind() == "binary_expression"
        || (size_node.kind() != "number_literal" && !size_text.chars().all(|c| c.is_numeric()));

    if !is_vla {
        // Check if it's a constant 0
        if size_text == "0" {
            let start_point = declarator.start_position();
            return Some(RuleViolation {
                rule_id: "ARR00-C".to_string(),
                severity: Severity::High,
                message: "Array declared with size 0. Zero-length arrays have undefined behavior."
                    .to_string(),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some(
                    "Use a positive constant size or validate variable size before declaration"
                        .to_string(),
                ),
                ..Default::default()
            });
        }
        return None; // Constant non-zero size is OK
    }

    // For VLAs with variable size, check if the size variable was validated
    // This is a heuristic check - we look for the size identifier
    if size_node.kind() == "identifier" {
        let size_var_name = size_text;

        // Check if this appears to be an unvalidated parameter or variable
        // Look for assignment of 0 or validation checks in the surrounding context
        if let Some(violation) = check_vla_size_validation(node, size_var_name, source, &declarator)
        {
            return Some(violation);
        }
    }

    None
}

fn check_vla_size_validation(
    decl_node: &Node,
    size_var: &str,
    source: &str,
    declarator: &Node,
) -> Option<RuleViolation> {
    // Look backwards in the source to find if size_var was assigned 0 or is unvalidated
    // First, try to find the containing function
    let function_node = find_containing_function(decl_node)?;

    // Get all variable declarations and assignments before this VLA declaration
    let vla_position = decl_node.start_byte();

    // Simple heuristic: check if we can find "size_var = 0" before the VLA
    let function_start = function_node.start_byte();
    let preceding_text = &source[function_start..vla_position];

    // Check for direct assignment of 0
    if preceding_text.contains(&format!("{} = 0", size_var))
        || preceding_text.contains(&format!("{}=0", size_var))
    {
        let start_point = declarator.start_position();
        return Some(RuleViolation {
            rule_id: "ARR00-C".to_string(),
            severity: Severity::High,
            message: format!(
                "Variable Length Array declared with size '{}' which is assigned 0. VLAs must have positive size.",
                size_var
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some("Validate that the size is positive before declaring the VLA".to_string()),
        ..Default::default()
        });
    }

    // Check if it's a function parameter without validation
    // This is a simplified check - in production, we'd need more sophisticated analysis
    if is_function_parameter(&function_node, size_var, source) {
        // Check if there's a validation before the VLA
        if !has_size_validation_before(preceding_text, size_var) {
            let start_point = declarator.start_position();
            return Some(RuleViolation {
                rule_id: "ARR00-C".to_string(),
                severity: Severity::Medium,
                message: format!(
                    "Variable Length Array declared with unvalidated parameter '{}'. Size could be zero or negative.",
                    size_var
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some("Add validation: if (size <= 0 || size > MAX_SIZE) return;".to_string()),
            ..Default::default()
            });
        }
    }

    None
}

// is_function_parameter() - now imported from ast_utils

fn is_loop_variable(var_name: &str, preceding_text: &str) -> bool {
    // Check if the variable is defined in a for loop initialization
    // Look for patterns like: for (type varname = ...; ...; ...)

    // Search for "for" statements and check if they contain our variable in the init section
    // Use a simple but effective approach: look for the variable name between "for (" and the first ";"

    let mut in_for_init = false;
    let mut paren_depth = 0;
    let mut chars = preceding_text.chars().peekable();
    let mut current_word = String::new();
    let mut for_init_content = String::new();

    while let Some(ch) = chars.next() {
        // Check for "for" keyword
        current_word.push(ch);
        if current_word.len() > 3 {
            current_word.remove(0);
        }

        if current_word == "for" {
            // Check if next non-whitespace char is '('
            let remaining: String = chars.clone().collect();
            if remaining.trim_start().starts_with('(') {
                in_for_init = true;
                for_init_content.clear();
                paren_depth = 0;
                continue;
            }
        }

        if in_for_init {
            if ch == '(' {
                paren_depth += 1;
                if paren_depth > 1 {
                    for_init_content.push(ch);
                }
            } else if ch == ')' {
                paren_depth -= 1;
                if paren_depth > 0 {
                    for_init_content.push(ch);
                }
            } else if ch == ';' && paren_depth == 1 {
                // End of for loop init section
                // Check if our variable name appears in the init content
                // Split by whitespace and special chars to find exact word matches
                let words: Vec<&str> = for_init_content
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .filter(|s| !s.is_empty())
                    .collect();

                if words.contains(&var_name) {
                    return true;
                }

                in_for_init = false;
                for_init_content.clear();
            } else if paren_depth >= 1 {
                for_init_content.push(ch);
            }
        }
    }

    false
}

fn has_size_validation_before(text: &str, size_var: &str) -> bool {
    // Check for common validation patterns
    // if (size == 0), if (size <= 0), if (size < 1), etc.
    // Also check for compound conditions with || or &&

    // Simple patterns
    let simple_patterns = [
        format!("{} == 0", size_var),
        format!("{} <= 0", size_var),
        format!("{} < 1", size_var),
        format!("0 == {}", size_var),
        format!("{}==0", size_var),
        format!("{}<=0", size_var),
        format!("{}<1", size_var),
    ];

    simple_patterns.iter().any(|pattern| text.contains(pattern))
}

fn check_dangerous_functions(node: &Node, source: &str) -> Option<RuleViolation> {
    // Check for calls to functions that demonstrate misunderstanding of array bounds
    let function = node.child_by_field_name("function")?;
    let func_text = &source[function.start_byte()..function.end_byte()];

    // gets() is inherently dangerous - ALWAYS indicates misunderstanding
    // There is NO safe way to use gets() as it has no bounds checking mechanism
    if func_text == "gets" {
        let start_point = node.start_position();
        return Some(RuleViolation {
            rule_id: "ARR00-C".to_string(),
            severity: Severity::Critical,
            message: "Use of gets() demonstrates misunderstanding of array bounds. It is deprecated and has no safe usage.".to_string(),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some("Use fgets(buffer, sizeof(buffer), stdin) which respects buffer size".to_string()),
        ..Default::default()
        });
    }

    // scanf/fscanf/sscanf with unbounded %s format specifier
    if func_text == "scanf" || func_text == "fscanf" || func_text == "sscanf" {
        // Get the arguments to check the format string
        let arguments = node.child_by_field_name("arguments")?;

        // Extract arguments (skip parentheses and commas)
        let mut args = Vec::new();
        for i in 0..arguments.child_count() {
            if let Some(child) = arguments.child(i) {
                let kind = child.kind();
                if kind != "," && kind != "(" && kind != ")" {
                    args.push(child);
                }
            }
        }

        // scanf(format, ...) - format is first arg
        // fscanf(stream, format, ...) - format is second arg
        // sscanf(str, format, ...) - format is second arg
        let format_arg_index = if func_text == "scanf" { 0 } else { 1 };

        if args.len() <= format_arg_index {
            return None;
        }

        let format_arg = args[format_arg_index];
        if format_arg.kind() == "string_literal" {
            let format_text = &source[format_arg.start_byte()..format_arg.end_byte()];

            // Check for unbounded %s (not %Ns where N is a number)
            // Pattern: %s that is NOT preceded by a digit
            if format_text.contains("%s") {
                // Check if it's an unbounded %s (not like %10s)
                // Look for %s that doesn't have a width specifier
                let has_unbounded_s = format_text.match_indices("%s").any(|(pos, _)| {
                    // Check character before % (if exists)
                    // If it's a digit, then we need to go back further to find the actual %
                    if pos > 0 {
                        let before_percent = &format_text[..pos];
                        // Find the actual % position by checking if there are digits before %s
                        if let Some(percent_pos) = before_percent.rfind('%') {
                            let between = &before_percent[percent_pos + 1..];
                            // If there are only digits between % and s, it's bounded like %10s
                            !between.chars().all(|c| c.is_ascii_digit())
                        } else {
                            true // Shouldn't happen, but treat as unbounded
                        }
                    } else {
                        true // %s at start of string
                    }
                });

                if has_unbounded_s {
                    let start_point = node.start_position();
                    return Some(RuleViolation {
                        rule_id: "ARR00-C".to_string(),
                        severity: Severity::Critical,
                        message: format!(
                            "Use of {}() with unbounded '%s' format specifier can overflow buffer. This demonstrates misunderstanding of array bounds.",
                            func_text
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(format!(
                            "Use a width specifier like '%Ns' where N is buffer size minus 1, e.g., {}(\"%9s\", buffer) for char buffer[10]",
                            func_text
                        )),
                    ..Default::default()
                    });
                }
            }
        }
    }

    None
}

fn check_obvious_string_overflow(node: &Node, source: &str) -> Option<RuleViolation> {
    // Check for obviously wrong strcat/strcpy calls where the source is clearly too large
    // This indicates fundamental misunderstanding of arrays
    // Example: char buf[10]; strcat(buf, "This is way too long");

    let function = node.child_by_field_name("function")?;
    let func_text = &source[function.start_byte()..function.end_byte()];

    // Check strcat, strcpy, sprintf, and snprintf
    let is_str_concat = func_text == "strcat" || func_text == "strcpy";
    let is_sprintf = func_text == "sprintf" || func_text == "snprintf";

    if !is_str_concat && !is_sprintf {
        return None;
    }

    // Get the arguments
    let arguments = node.child_by_field_name("arguments")?;

    // Extract destination and source arguments (skip parentheses and commas)
    let mut args = Vec::new();
    for i in 0..arguments.child_count() {
        if let Some(child) = arguments.child(i) {
            let kind = child.kind();
            if kind != "," && kind != "(" && kind != ")" {
                args.push(child);
            }
        }
    }

    // For sprintf/snprintf: sprintf(dest, format, arg1, arg2, ...)
    // For strcat/strcpy: strcat(dest, src)
    let (dest, src) = if is_sprintf {
        // sprintf: first arg is dest, third arg (index 2) is typically the string to format
        // We'll check if there's a %s in the format string and use the next argument
        if args.len() < 3 {
            return None; // Need at least dest, format, and one argument
        }

        // Check if format string contains %s
        let format_arg = args[1];
        let format_text = &source[format_arg.start_byte()..format_arg.end_byte()];

        if !format_text.contains("%s") {
            return None; // Only check simple %s formatting for now
        }

        (args[0], args[2]) // dest and first argument after format
    } else {
        // strcat/strcpy: standard dest, src
        if args.len() < 2 {
            return None;
        }
        (args[0], args[1])
    };

    // Get source length - either from string literal or from variable initialized with literal
    let src_len = if src.kind() == "string_literal" {
        // Direct string literal
        let src_text = &source[src.start_byte()..src.end_byte()];
        Some(src_text.trim_matches('"').len())
    } else if src.kind() == "identifier" {
        // Variable - try to find its initialization
        let src_var_name = &source[src.start_byte()..src.end_byte()];
        find_string_literal_length(src_var_name, node, source)
    } else {
        None
    };

    let src_len = src_len?;

    // Get destination identifier name
    let dest_name = &source[dest.start_byte()..dest.end_byte()];

    // Find the destination array declaration to get its size
    let function_node = find_containing_function(node)?;
    let function_start = function_node.start_byte();
    let call_position = node.start_byte();
    let preceding_text = &source[function_start..call_position];

    // Look for array declaration
    if let Some(dest_size) = find_array_size(dest_name, preceding_text) {
        // For strcat, we need space for existing content + new content + null terminator
        // For strcpy, we need space for new content + null terminator
        let required_space = if func_text == "strcat" {
            // We need to estimate existing content, but for a simple check,
            // just verify the source alone fits
            src_len + 1 // +1 for null terminator
        } else {
            src_len + 1 // +1 for null terminator
        };

        if required_space > dest_size {
            let start_point = node.start_position();
            let src_display = &source[src.start_byte()..src.end_byte()];
            return Some(RuleViolation {
                rule_id: "ARR00-C".to_string(),
                severity: Severity::Critical,
                message: format!(
                    "{}({}, {}) will overflow buffer. Source string is {} bytes but destination has only {} bytes.",
                    func_text,
                    dest_name,
                    src_display,
                    src_len,
                    dest_size
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some(format!(
                    "Use safer alternatives like strncat/strncpy with proper size limits, or increase buffer size to at least {} bytes",
                    required_space
                )),
            ..Default::default()
            });
        }
    }

    None
}

fn check_memcpy_size_mismatch(node: &Node, source: &str) -> Option<RuleViolation> {
    // Check for memcpy/memmove where size argument uses wrong array
    // Pattern: memcpy(dest, source, sizeof(source)) where dest is smaller than source
    // This indicates misunderstanding of array bounds

    let function = node.child_by_field_name("function")?;
    let func_text = &source[function.start_byte()..function.end_byte()];

    // Only check memcpy and memmove
    if func_text != "memcpy" && func_text != "memmove" {
        return None;
    }

    // Get the arguments
    let arguments = node.child_by_field_name("arguments")?;

    // Extract dest, src, and size arguments (skip parentheses and commas)
    let mut args = Vec::new();
    for i in 0..arguments.child_count() {
        if let Some(child) = arguments.child(i) {
            let kind = child.kind();
            if kind != "," && kind != "(" && kind != ")" {
                args.push(child);
            }
        }
    }

    if args.len() < 3 {
        return None;
    }

    let dest = args[0];
    let src = args[1];
    let size_arg = args[2];

    // Check if size argument is sizeof(something)
    if size_arg.kind() != "sizeof_expression" {
        return None; // Only check obvious sizeof misuse
    }

    // Extract what sizeof is applied to
    let sizeof_arg = size_arg.child_by_field_name("value")?;
    let sizeof_arg_text = &source[sizeof_arg.start_byte()..sizeof_arg.end_byte()];

    // Get dest and src names
    let dest_name = &source[dest.start_byte()..dest.end_byte()];
    let src_name = &source[src.start_byte()..src.end_byte()];

    // Find the containing function to look up array sizes
    let function_node = find_containing_function(node)?;
    let function_start = function_node.start_byte();
    let call_position = node.start_byte();
    let preceding_text = &source[function_start..call_position];

    // Check if sizeof is applied to the source when it should be dest
    // Pattern: memcpy(dest, src, sizeof(src)) where sizeof(dest) < sizeof(src)
    // Note: sizeof_arg_text may have parentheses like "(source)"
    let sizeof_stripped = sizeof_arg_text.trim_matches('(').trim_matches(')').trim();

    if sizeof_stripped == src_name {
        // Get sizes of both arrays
        let dest_size = find_array_size(dest_name, preceding_text)?;
        let src_size = find_array_size(src_name, preceding_text)?;

        if dest_size < src_size {
            let start_point = node.start_position();
            return Some(RuleViolation {
                rule_id: "ARR00-C".to_string(),
                severity: Severity::Critical,
                message: format!(
                    "{}({}, {}, sizeof({})) will overflow destination. Destination array '{}' has {} elements but source '{}' has {} elements.",
                    func_text,
                    dest_name,
                    src_name,
                    src_name,
                    dest_name,
                    dest_size,
                    src_name,
                    src_size
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some(format!(
                    "Use sizeof({}) instead of sizeof({}) to avoid buffer overflow",
                    dest_name,
                    src_name
                )),
            ..Default::default()
            });
        }
    }

    None
}

fn check_memory_operation_overflow(node: &Node, source: &str) -> Option<RuleViolation> {
    // Check for memory operations (memset, memcpy, memmove) where the size argument
    // exceeds the actual buffer size
    // Pattern: int arr[5]; memset(arr, 0, 100); // 100 bytes > 5*sizeof(int) = 20 bytes

    let function = node.child_by_field_name("function")?;
    let func_text = &source[function.start_byte()..function.end_byte()];

    // Check for memory operation functions
    let is_memset = func_text == "memset";
    let is_memcpy = func_text == "memcpy";
    let is_memmove = func_text == "memmove";

    if !is_memset && !is_memcpy && !is_memmove {
        return None;
    }

    // Get the arguments
    let arguments = node.child_by_field_name("arguments")?;

    // Extract arguments (skip parentheses and commas)
    let mut args = Vec::new();
    for i in 0..arguments.child_count() {
        if let Some(child) = arguments.child(i) {
            let kind = child.kind();
            if kind != "," && kind != "(" && kind != ")" {
                args.push(child);
            }
        }
    }

    // memset(ptr, value, size) - check args[0] and args[2]
    // memcpy(dest, src, size) - check args[0] and args[2]
    // memmove(dest, src, size) - check args[0] and args[2]

    if args.len() < 3 {
        return None;
    }

    let buffer = args[0];
    let size_arg = args[2];

    // We're looking for constant literal size arguments
    if size_arg.kind() != "number_literal" {
        return None;
    }

    let size_text = &source[size_arg.start_byte()..size_arg.end_byte()];
    let size_bytes: usize = size_text.parse().ok()?;

    // Get buffer name
    let buffer_name = &source[buffer.start_byte()..buffer.end_byte()];

    // Find the containing function to look up array size
    let function_node = find_containing_function(node)?;
    let function_start = function_node.start_byte();
    let call_position = node.start_byte();
    let preceding_text = &source[function_start..call_position];

    // Try to find the array size
    let array_size = find_array_size(buffer_name, preceding_text)?;

    // Calculate actual buffer size in bytes
    // We need to determine the element type to get sizeof
    // For now, assume int (4 bytes) as default, but try to detect the type
    let element_size = find_element_size(buffer_name, preceding_text);
    let buffer_size_bytes = array_size * element_size;

    if size_bytes > buffer_size_bytes {
        let start_point = node.start_position();
        return Some(RuleViolation {
            rule_id: "ARR00-C".to_string(),
            severity: Severity::Critical,
            message: format!(
                "{}() call writes {} bytes to buffer '{}' which is only {} bytes ({} elements × {} bytes). This causes buffer overflow.",
                func_text,
                size_bytes,
                buffer_name,
                buffer_size_bytes,
                array_size,
                element_size
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(format!(
                "Use the actual buffer size: {}({}, ..., {}) or {}({}, ..., sizeof({}))",
                func_text,
                buffer_name,
                buffer_size_bytes,
                func_text,
                buffer_name,
                buffer_name
            )),
        ..Default::default()
        });
    }

    None
}

// Size analysis functions - now imported from size_analysis module:
// - find_element_size()
// - find_string_literal_length()

fn check_loop_exceeds_allocation(node: &Node, source: &str) -> Option<RuleViolation> {
    // Check for loops that exceed dynamically allocated memory size
    // Pattern: arr = malloc(5 * sizeof(int)); for (i = 0; i < 10; i++) { arr[i] = ...; }
    // or: arr = realloc(arr, 3 * sizeof(int)); for (i = 0; i < 5; i++) { arr[i] = ...; }

    // Get the loop condition
    let condition = node.child_by_field_name("condition")?;
    if condition.kind() != "binary_expression" {
        return None;
    }

    let operator_node = condition.child_by_field_name("operator")?;
    let operator = &source[operator_node.start_byte()..operator_node.end_byte()];
    let left = condition.child_by_field_name("left")?;
    let right = condition.child_by_field_name("right")?;

    // Extract loop variable and bound
    let (loop_var, bound_node) = if left.kind() == "identifier" && right.kind() == "number_literal"
    {
        (left, right)
    } else if right.kind() == "identifier" && left.kind() == "number_literal" {
        (right, left)
    } else {
        return None;
    };

    let loop_var_name = &source[loop_var.start_byte()..loop_var.end_byte()];
    let bound_text = &source[bound_node.start_byte()..bound_node.end_byte()];
    let loop_bound: usize = match bound_text.parse() {
        Ok(n) => n,
        Err(_) => return None,
    };

    // Get the loop body
    let body = node.child_by_field_name("body")?;
    let body_text = &source[body.start_byte()..body.end_byte()];

    // Check if loop variable is used as array index
    let subscript_pattern = format!("[{}]", loop_var_name);
    if !body_text.contains(&subscript_pattern) {
        return None;
    }

    // Extract array name
    let array_name = extract_array_name_from_subscript(body_text, loop_var_name)?;

    // Look for malloc/realloc calls for this pointer
    let function_node = find_containing_function(node)?;
    let function_start = function_node.start_byte();
    let loop_position = node.start_byte();
    let preceding_text = &source[function_start..loop_position];

    // Find the most recent malloc/realloc for this pointer
    if let Some(alloc_size) = find_allocation_size(&array_name, preceding_text) {
        // Check if loop bound exceeds allocation size
        // For operator <, loop goes from 0 to bound-1
        // For operator <=, loop goes from 0 to bound
        let max_index = if operator == "<" {
            loop_bound.saturating_sub(1)
        } else if operator == "<=" {
            loop_bound
        } else {
            return None; // Don't handle > or >= for now
        };

        if max_index >= alloc_size {
            let start_point = node.start_position();
            return Some(RuleViolation {
                rule_id: "ARR00-C".to_string(),
                severity: Severity::Critical,
                message: format!(
                    "Loop accesses up to index {} but dynamically allocated array '{}' has size {}. This causes out-of-bounds access.",
                    max_index, array_name, alloc_size
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some(format!(
                    "Ensure loop bound does not exceed allocated size. Change to '{} < {}' to match allocation size.",
                    loop_var_name, alloc_size
                )),
            ..Default::default()
            });
        }
    }

    None
}

// find_allocation_size() - now imported from size_analysis module

fn check_loop_bound_exceeds_array(node: &Node, source: &str) -> Option<RuleViolation> {
    // Check for loops where the bound allows accessing out-of-bounds indices
    // Pattern: for (int i = 0; i <= 10; i++) { arr[i] = ...; } where arr[10]
    // The <= allows i to reach 10, which is out of bounds

    // Get the loop condition to analyze the bound
    let condition = node.child_by_field_name("condition")?;

    // Parse the condition to extract loop variable and bound
    if condition.kind() != "binary_expression" {
        return None;
    }

    let operator_node = condition.child_by_field_name("operator")?;
    let operator = &source[operator_node.start_byte()..operator_node.end_byte()];

    let left = condition.child_by_field_name("left")?;
    let right = condition.child_by_field_name("right")?;

    // Determine loop variable and bound
    let (loop_var, bound_node, is_inclusive) =
        if left.kind() == "identifier" && right.kind() == "number_literal" {
            let inclusive = operator == "<=" || operator == ">=";
            (left, right, inclusive)
        } else if right.kind() == "identifier" && left.kind() == "number_literal" {
            let inclusive = operator == ">=" || operator == "<=";
            (right, left, inclusive)
        } else {
            return None;
        };

    // Only care about inclusive bounds for now (<=)
    if !is_inclusive {
        return None;
    }

    let loop_var_name = &source[loop_var.start_byte()..loop_var.end_byte()];
    let bound_text = &source[bound_node.start_byte()..bound_node.end_byte()];
    let bound_value: usize = match bound_text.parse() {
        Ok(n) => n,
        Err(_) => return None,
    };

    // Get the loop body
    let body = node.child_by_field_name("body")?;

    // Look for array access using the loop variable: arr[loop_var]
    let body_text = &source[body.start_byte()..body.end_byte()];
    let subscript_pattern = format!("[{}]", loop_var_name);

    if !body_text.contains(&subscript_pattern) {
        return None; // No array access with this loop variable
    }

    // Find arrays being accessed in the loop body
    // Look for pattern: array_name[loop_var]
    let function_node = find_containing_function(node)?;
    let function_start = function_node.start_byte();
    let loop_position = node.start_byte();
    let preceding_text = &source[function_start..loop_position];

    // Try to find array declarations and check if bound exceeds array size
    // Parse body_text to find identifiers before [loop_var]
    if let Some(array_name) = extract_array_name_from_subscript(body_text, loop_var_name) {
        if let Some(array_size) = find_array_size(&array_name, preceding_text) {
            // Check if loop bound allows out-of-bounds access
            // For arr[10] with size 10, valid indices are 0-9
            // If loop is i <= 10, then i can be 10, which is out of bounds
            if bound_value >= array_size {
                let start_point = node.start_position();
                return Some(RuleViolation {
                    rule_id: "ARR00-C".to_string(),
                    severity: Severity::Critical,
                    message: format!(
                        "Loop bound allows index {} but array '{}' has size {}. Valid indices are 0-{}. Using '<=' instead of '<' causes off-by-one error.",
                        bound_value, array_name, array_size, array_size - 1
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some(format!(
                        "Change loop condition to '{} < {}' instead of '{} <= {}'",
                        loop_var_name, bound_value, loop_var_name, bound_value
                    )),
                ..Default::default()
                });
            }
        }
    }

    None
}

fn extract_array_name_from_subscript(body_text: &str, loop_var: &str) -> Option<String> {
    // Find pattern: identifier[loop_var]
    let pattern = format!("[{}]", loop_var);
    if let Some(pos) = body_text.find(&pattern) {
        // Look backwards from '[' to find the identifier
        let before_bracket = &body_text[..pos];

        // Find the last identifier before the bracket
        let mut end = before_bracket.len();
        while end > 0
            && before_bracket
                .chars()
                .nth(end - 1)
                .is_some_and(|c| c.is_whitespace())
        {
            end -= 1;
        }

        let mut start = end;
        while start > 0 {
            let ch = before_bracket.chars().nth(start - 1)?;
            if ch.is_alphanumeric() || ch == '_' {
                start -= 1;
            } else {
                break;
            }
        }

        if start < end {
            return Some(before_bracket[start..end].to_string());
        }
    }
    None
}

fn check_loop_array_access(node: &Node, source: &str) -> Option<RuleViolation> {
    // Check for loops that use unvalidated/uninitialized variables as bounds when accessing arrays
    // Patterns:
    // 1. for (int i = 0; i < user_input; i++) { array[i] = ...; }
    // 2. for (int i = 0; i < uninitialized_var; i++) { array[i] = ...; }

    // Get the loop condition to find the bound variable
    let condition = node.child_by_field_name("condition")?;
    let bound_var = extract_loop_bound_variable(&condition, source)?;

    // Get the loop body
    let body = node.child_by_field_name("body")?;

    // Check if body contains array access
    let has_array_access = contains_array_access(&body);
    if !has_array_access {
        return None;
    }

    // Look backwards in the function to see if bound_var was populated from user input or is uninitialized
    let function_node = find_containing_function(node)?;
    let loop_position = node.start_byte();
    let function_start = function_node.start_byte();
    let preceding_text = &source[function_start..loop_position];

    // Check if bound_var is a function parameter - if so, it's the caller's responsibility
    if is_function_parameter(&function_node, &bound_var, source) {
        return None; // Function parameters are assumed to be valid
    }

    // Check for scanf/fscanf reading into the bound variable
    if is_user_input_variable(&bound_var, preceding_text) {
        // Check if there's validation before the loop
        if !has_validation_before_loop(&bound_var, preceding_text, loop_position, source) {
            let start_point = node.start_position();
            return Some(RuleViolation {
                rule_id: "ARR00-C".to_string(),
                severity: Severity::High,
                message: format!(
                    "Loop uses unvalidated user input '{}' as bound for array access. This can cause out-of-bounds access.",
                    bound_var
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some(format!(
                    "Validate '{}' against array size before using in loop: if ({} < 0 || {} > ARRAY_SIZE) {{ /* error */ }}",
                    bound_var, bound_var, bound_var
                )),
            ..Default::default()
            });
        }
    }
    // Check if the variable is uninitialized
    else if is_uninitialized_variable(&bound_var, preceding_text) {
        let start_point = node.start_position();
        return Some(RuleViolation {
            rule_id: "ARR00-C".to_string(),
            severity: Severity::High,
            message: format!(
                "Loop uses uninitialized variable '{}' as bound for array access. This has indeterminate value and can cause out-of-bounds access.",
                bound_var
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(format!(
                "Initialize '{}' to a valid value before using it in the loop",
                bound_var
            )),
        ..Default::default()
        });
    }

    None
}

fn extract_loop_bound_variable(condition: &Node, source: &str) -> Option<String> {
    // For condition like "i < count", extract "count"
    // Handle binary expressions: i < var, i <= var, var > i, etc.
    if condition.kind() == "binary_expression" {
        let left = condition.child_by_field_name("left")?;
        let right = condition.child_by_field_name("right")?;

        // Check right side first (most common: i < bound)
        if right.kind() == "identifier" {
            return Some(source[right.start_byte()..right.end_byte()].to_string());
        }
        // Check left side (less common: bound > i)
        if left.kind() == "identifier" {
            let text = &source[left.start_byte()..left.end_byte()];
            // Avoid returning the loop variable itself
            if text != "i" && text != "j" && text != "k" {
                return Some(text.to_string());
            }
        }
    }
    None
}

fn contains_array_access(node: &Node) -> bool {
    // Check if this node or any child is a subscript_expression (array access)
    if node.kind() == "subscript_expression" {
        return true;
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if contains_array_access(&child) {
                return true;
            }
        }
    }

    false
}

// Variable analysis functions - now imported from variable_analysis module:
// - is_user_input_variable()
// - has_validation_before_loop()
// - is_uninitialized_variable()

fn check_subscript_bounds(node: &Node, source: &str) -> Option<RuleViolation> {
    // Check for array subscript with unvalidated index
    // Pattern: arr[index] where index comes from scanf or is a function parameter without validation

    // Only flag true arrays, not pointer subscripts
    let array_node = node.child_by_field_name("argument")?;
    if array_node.kind() == "identifier" {
        let arr_name = &source[array_node.start_byte()..array_node.end_byte()];
        if let Some(fn_node) = find_containing_function(node) {
            if !has_array_declaration(&fn_node, arr_name, source) {
                return None;
            }
        }
    }

    // Get the index expression from the subscript
    let index_node = node.child_by_field_name("index")?;

    // Check if index is an identifier (variable)
    if index_node.kind() != "identifier" {
        return None; // Only check variable indices for now
    }

    let index_var = &source[index_node.start_byte()..index_node.end_byte()];

    // Find the containing function to check context
    let function_node = find_containing_function(node)?;

    // Get the function body text up to this point
    let function_start = function_node.start_byte();
    let subscript_position = node.start_byte();
    let preceding_text = &source[function_start..subscript_position];

    // Check if index_var is a loop variable (defined in a for loop)
    // Pattern: for (...; index_var ...; ...) or for (... index_var = ...
    if is_loop_variable(index_var, preceding_text) {
        return None; // Loop variables are assumed to be bounded by the loop condition
    }

    // Check if this is a function parameter (indicates it comes from caller without validation)
    if is_function_parameter(&function_node, index_var, source) {
        // Static functions whose index param is a user-defined type (e.g. an enum typedef
        // like led_id_t) have a closed caller set with enum-constrained index values.
        // Requiring runtime bounds checks there produces FPs for enum-indexed arrays.
        if is_static_function(&function_node, source)
            && is_user_defined_param_type(&function_node, index_var, source)
        {
            return None;
        }
        // Check if there's bounds validation before this subscript
        if !has_bounds_validation(index_var, preceding_text) {
            let start_point = node.start_position();
            return Some(RuleViolation {
                rule_id: "ARR00-C".to_string(),
                severity: Severity::High,
                message: format!(
                    "Array subscript uses function parameter '{}' without bounds checking. Caller could pass invalid index.",
                    index_var
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some(format!(
                    "Add bounds checking for '{}' before using it as an array index",
                    index_var
                )),
            ..Default::default()
            });
        }
    }

    // Check if the index variable comes from scanf without validation
    if is_user_input_variable(index_var, preceding_text)
        && !has_bounds_validation(index_var, preceding_text)
    {
        let start_point = node.start_position();
        return Some(RuleViolation {
            rule_id: "ARR00-C".to_string(),
            severity: Severity::High,
            message: format!(
                "Array subscript uses unvalidated user input '{}' from scanf(). This can cause out-of-bounds access.",
                index_var
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(format!(
                "Validate '{}' against array bounds before using it as an index",
                index_var
            )),
        ..Default::default()
        });
    }

    None
}

/// Returns true if the named parameter of `func_node` is declared with a non-primitive
/// (user-defined) type such as an enum typedef (e.g., `led_id_t`).
fn is_user_defined_param_type(func_node: &Node, param_name: &str, source: &str) -> bool {
    let primitive_types = [
        "int",
        "long",
        "short",
        "char",
        "float",
        "double",
        "void",
        "signed",
        "unsigned",
        "size_t",
        "ssize_t",
        "ptrdiff_t",
        "intptr_t",
        "uintptr_t",
        "bool",
        "_Bool",
        "int8_t",
        "int16_t",
        "int32_t",
        "int64_t",
        "uint8_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
    ];
    if let Some(declarator) = func_node.child_by_field_name("declarator") {
        if let Some(param_list) = find_parameter_list_node(&declarator) {
            for i in 0..param_list.child_count() {
                if let Some(param) = param_list.child(i) {
                    if param.kind() != "parameter_declaration" {
                        continue;
                    }
                    let param_text = &source[param.start_byte()..param.end_byte()];
                    if !param_text.contains(param_name) {
                        continue;
                    }
                    if let Some(type_node) = param.child_by_field_name("type") {
                        let type_text = &source[type_node.start_byte()..type_node.end_byte()];
                        let stripped = type_text
                            .replace("const", "")
                            .replace("volatile", "")
                            .replace("restrict", "")
                            .replace("struct", "")
                            .replace("union", "")
                            .replace("enum", "");
                        let stripped = stripped.trim();
                        return !primitive_types.contains(&stripped);
                    }
                }
            }
        }
    }
    false
}

fn find_parameter_list_node<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    if node.kind() == "parameter_list" {
        return Some(*node);
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if let Some(found) = find_parameter_list_node(&child) {
                return Some(found);
            }
        }
    }
    None
}

/// Returns true if `function_node` is declared `static` or uses a STATIC macro prefix.
fn is_static_function(function_node: &Node, source: &str) -> bool {
    for i in 0..function_node.child_count() {
        if let Some(child) = function_node.child(i) {
            if child.kind() == "storage_class_specifier" {
                if &source[child.start_byte()..child.end_byte()] == "static" {
                    return true;
                }
            }
        }
    }
    // Also match project-specific STATIC macros (e.g., STATIC, LIN_STATIC_INLINE).
    let func_text = &source[function_node.start_byte()..function_node.end_byte()];
    let before_paren = func_text.split('(').next().unwrap_or("");
    before_paren
        .split_whitespace()
        .any(|tok| tok.contains("STATIC"))
}

fn check_uninitialized_array_read(node: &Node, source: &str) -> Option<RuleViolation> {
    // Check for reading from an uninitialized array
    // Pattern: int arr[10]; ... printf("%d", arr[i]);
    // The array is declared but never written to before being read

    // Only flag uninitialized reads that occur inside loops
    // Single element accesses are less critical (might be intentional undefined behavior check)
    if !is_inside_loop(node) {
        return None;
    }

    // Get the array being accessed
    let array_node = node.child_by_field_name("argument")?;
    if array_node.kind() != "identifier" {
        return None;
    }

    let array_name = &source[array_node.start_byte()..array_node.end_byte()];

    // Check if this is a read (not a write)
    // If the subscript is on the left side of an assignment, it's a write
    if is_write_context(node) {
        return None; // Writing to array, not reading
    }

    // Look backwards in the function to check if array was initialized
    let function_node = find_containing_function(node)?;
    let function_start = function_node.start_byte();
    let subscript_position = node.start_byte();
    let preceding_text = &source[function_start..subscript_position];

    // Only flag true array declarations (type name[SIZE]), not pointers
    if !has_array_declaration(&function_node, array_name, source) {
        return None; // Not a local array — pointer or parameter
    }

    // Check if it's a function parameter (parameters can be passed initialized)
    if is_function_parameter(&function_node, array_name, source) {
        return None; // Function parameters are assumed to be initialized by caller
    }

    // Check if array has been initialized (has assignment or initializer)
    // Look for patterns:
    // 1. Declaration with initializer: int arr[10] = {...}
    // 2. Assignment: arr[i] = ...
    let init_with_braces = format!("{}[", array_name);
    if let Some(decl_pos) = preceding_text.rfind(&init_with_braces) {
        let after_decl = &preceding_text[decl_pos..];
        // Check if declaration has an initializer (= {...)
        if after_decl.contains("=")
            && after_decl.find('=').unwrap() < after_decl.find(';').unwrap_or(usize::MAX)
        {
            return None; // Array has initializer
        }
    }

    // Check if there are any writes to the array before this read
    let write_pattern = format!("{}[", array_name);
    let mut found_write = false;

    // Simple heuristic: look for array_name[...] = on the left side of assignment
    for line in preceding_text.lines() {
        if line.contains(&write_pattern) && line.contains('=') {
            // Check if the array subscript comes before the =
            if let Some(bracket_pos) = line.find(&write_pattern) {
                if let Some(eq_pos) = line.find('=') {
                    // Make sure it's not ==, !=, <=, >=
                    let is_assignment = !line[..eq_pos].ends_with('!')
                        && !line[..eq_pos].ends_with('<')
                        && !line[..eq_pos].ends_with('>')
                        && !line[eq_pos..].starts_with("==");

                    if bracket_pos < eq_pos && is_assignment {
                        found_write = true;
                        break;
                    }
                }
            }
        }
    }

    if !found_write {
        let start_point = node.start_position();
        return Some(RuleViolation {
            rule_id: "ARR00-C".to_string(),
            severity: Severity::Critical,
            message: format!(
                "Reading from uninitialized array '{}' inside a loop. Array was declared but never initialized before being read.",
                array_name
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(format!(
                "Initialize array '{}' before reading: int {}[N] = {{0}}; or assign values before use",
                array_name, array_name
            )),
        ..Default::default()
        });
    }

    None
}

// is_inside_loop() - now imported from ast_utils
// is_write_context() - now imported from ast_utils

fn check_use_after_free(node: &Node, source: &str) -> Option<RuleViolation> {
    // Check for array/pointer access after free()
    // Pattern: free(ptr); ... ptr[i] = value;

    // Get the array being accessed
    let array_node = node.child_by_field_name("argument")?;
    if array_node.kind() != "identifier" {
        return None; // Only check simple identifiers
    }

    let array_name = &source[array_node.start_byte()..array_node.end_byte()];

    // Look backwards in the function to see if this pointer was freed
    let function_node = find_containing_function(node)?;
    let function_start = function_node.start_byte();
    let subscript_position = node.start_byte();
    let preceding_text = &source[function_start..subscript_position];

    // Check if free(array_name) appears before this access
    let free_pattern = format!("free({})", array_name);
    let free_pattern_space = format!("free ({})", array_name); // Some code has space after free

    if preceding_text.contains(&free_pattern) || preceding_text.contains(&free_pattern_space) {
        let start_point = node.start_position();
        return Some(RuleViolation {
            rule_id: "ARR00-C".to_string(),
            severity: Severity::Critical,
            message: format!(
                "Array/pointer '{}' is accessed after being freed. This is use-after-free, causing undefined behavior.",
                array_name
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(format!(
                "Do not access '{}' after calling free(). Set pointer to NULL after freeing: free({}); {} = NULL;",
                array_name, array_name, array_name
            )),
        ..Default::default()
        });
    }

    None
}

fn check_comma_in_subscript(node: &Node, source: &str) -> Option<RuleViolation> {
    // Check for comma operator inside array subscript
    // Pattern: arr[0,2] instead of arr[0][2]
    // This is a common misunderstanding - the comma operator evaluates both expressions
    // and returns the second one, so arr[0,2] is actually arr[2], not arr[0][2]

    // Get the full subscript text (including brackets)
    let subscript_text = &source[node.start_byte()..node.end_byte()];

    // Check if it matches the pattern of having a comma in the subscript
    // Look for [...,...] pattern
    if let Some(open_bracket) = subscript_text.find('[') {
        if let Some(close_bracket) = subscript_text.rfind(']') {
            let inside_brackets = &subscript_text[open_bracket + 1..close_bracket];

            // Check if there's a comma in the subscript content
            if inside_brackets.contains(',') {
                // Make sure it's not a function call like arr[func(a,b)]
                // Count parentheses - if balanced at 0 and no open paren before comma, it's the comma operator
                let mut paren_depth = 0;
                let mut found_comma_at_depth_zero = false;

                for ch in inside_brackets.chars() {
                    match ch {
                        '(' => paren_depth += 1,
                        ')' => paren_depth -= 1,
                        ',' if paren_depth == 0 => {
                            found_comma_at_depth_zero = true;
                            break;
                        }
                        _ => {}
                    }
                }

                if found_comma_at_depth_zero {
                    let array_node = node.child_by_field_name("argument");
                    let array_name = if let Some(arr) = array_node {
                        &source[arr.start_byte()..arr.end_byte()]
                    } else {
                        "array"
                    };

                    let start_point = node.start_position();
                    return Some(RuleViolation {
                        rule_id: "ARR00-C".to_string(),
                        severity: Severity::Critical,
                        message: format!(
                            "Incorrect multidimensional array access '{}'. The comma operator causes this to evaluate to the last expression only, not accessing element [i][j].",
                            subscript_text
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(format!(
                            "For 2D array access, use multiple subscripts like '{}[i][j]' instead of '{}[i,j]'",
                            array_name,
                            array_name
                        )),
                    ..Default::default()
                    });
                }
            }
        }
    }

    None
}

fn check_constant_out_of_bounds(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
) -> Option<RuleViolation> {
    // Check for array access with a constant literal index that exceeds bounds
    // Pattern: arr[5] where arr is declared as arr[5] or smaller

    // Get the index expression from the subscript
    let index_node = node.child_by_field_name("index")?;

    // Check if index is a number literal (constant)
    if index_node.kind() != "number_literal" {
        return None; // Only check constant indices
    }

    let index_text = &source[index_node.start_byte()..index_node.end_byte()];

    // Get the array being accessed first (we'll need it for the error message)
    let array_node = node.child_by_field_name("argument")?;
    if array_node.kind() != "identifier" {
        return None; // Only check simple array identifiers for now
    }

    let array_name = &source[array_node.start_byte()..array_node.end_byte()];

    // Check for negative index first (starts with -)
    if index_text.starts_with('-') {
        let start_point = node.start_position();
        return Some(RuleViolation {
            rule_id: "ARR00-C".to_string(),
            severity: Severity::Critical,
            message: format!(
                "Array subscript {} is negative. Array indices must be non-negative (0 or greater).",
                index_text
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(format!(
                "Array '{}' requires a non-negative index. Negative indices access memory before the array.",
                array_name
            )),
        ..Default::default()
        });
    }

    // Parse as unsigned integer for positive bounds checking
    let index_value: usize = match index_text.parse() {
        Ok(n) => n,
        Err(_) => return None,
    };

    // Only check true array declarations, not subscripted pointers
    let function_node = find_containing_function(node)?;
    if !has_array_declaration(&function_node, array_name, source) {
        return None;
    }

    // Resolve the array's declared size from its AST declaration, not from a
    // fragile text scan. The text heuristic (find_array_size) latched onto
    // subscript *uses* and failed to recognize user-typed declarations
    // (`Vector2 point[12]`), miscounting braced/const-expr-sized arrays and
    // flagging every legitimate access as OOB. resolve_declared_array_size
    // returns None when the bound is a non-constant expression it cannot
    // evaluate (e.g. `points[2*SPLINE_SEGMENT_DIVISIONS + 2]`), so we stay
    // silent rather than guess a too-small bound.
    if let Some(array_size) = resolve_declared_array_size(node, array_name, source, macros) {
        // Check if index is out of bounds (valid indices are 0 to size-1)
        if index_value >= array_size {
            let start_point = node.start_position();
            return Some(RuleViolation {
                rule_id: "ARR00-C".to_string(),
                severity: Severity::Critical,
                message: format!(
                    "Array subscript {} is out of bounds for array '{}[{}]'. Valid indices are 0 to {}.",
                    index_value, array_name, array_size, array_size.saturating_sub(1)
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some(format!(
                    "Use a valid index in the range [0, {}] for array '{}'",
                    array_size.saturating_sub(1), array_name
                )),
            ..Default::default()
            });
        }
    }

    None
}

// has_bounds_validation() - now imported from variable_analysis module

fn check_boundary_value_index(node: &Node, source: &str) -> Option<RuleViolation> {
    // Check for array subscript using a variable initialized to boundary values
    // Pattern: unsigned int idx = UINT_MAX; ... arr[idx]
    // This indicates misunderstanding of safe array indexing

    // Get the index expression from the subscript
    let index_node = node.child_by_field_name("index")?;

    // Check if index is an identifier (variable)
    if index_node.kind() != "identifier" {
        return None; // Only check variable indices
    }

    let index_var = &source[index_node.start_byte()..index_node.end_byte()];

    // Find the containing function to check context
    let function_node = find_containing_function(node)?;
    let function_start = function_node.start_byte();
    let subscript_position = node.start_byte();
    let preceding_text = &source[function_start..subscript_position];

    // Check if this variable was initialized to a boundary value
    if let Some(boundary_value) = is_initialized_to_boundary_value(index_var, preceding_text) {
        // Check if there's validation before using as array index
        if !has_bounds_validation(index_var, preceding_text) {
            let start_point = node.start_position();
            return Some(RuleViolation {
                rule_id: "ARR00-C".to_string(),
                severity: Severity::High,
                message: format!(
                    "Array subscript uses variable '{}' initialized to boundary value '{}' without bounds checking. This can cause overflow or out-of-bounds access.",
                    index_var,
                    boundary_value
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some(format!(
                    "Validate '{}' against array bounds before using it as an index, or avoid initializing indices to boundary values",
                    index_var
                )),
            ..Default::default()
            });
        }
    }

    None
}

fn is_initialized_to_boundary_value(var_name: &str, preceding_text: &str) -> Option<&'static str> {
    // Check if variable was initialized to a boundary value
    // Patterns:
    // unsigned int idx = UINT_MAX;
    // int idx = INT_MAX;
    // size_t idx = SIZE_MAX;

    let boundary_values = [
        "UINT_MAX",
        "INT_MAX",
        "SIZE_MAX",
        "ULONG_MAX",
        "LONG_MAX",
        "ULLONG_MAX",
        "LLONG_MAX",
    ];

    // Look for variable declaration/initialization
    let var_pattern = format!("{} =", var_name);
    if let Some(init_pos) = preceding_text.rfind(&var_pattern) {
        let after_eq = &preceding_text[init_pos..];

        // Check if any boundary value appears in the initialization
        for &boundary in &boundary_values {
            if after_eq.contains(boundary) {
                // Make sure it's before a semicolon (part of the same statement)
                if let Some(semicolon_pos) = after_eq.find(';') {
                    let init_statement = &after_eq[..semicolon_pos];
                    if init_statement.contains(boundary) {
                        return Some(boundary);
                    }
                }
            }
        }
    }

    None
}

fn check_return_local_array(node: &Node, source: &str) -> Option<RuleViolation> {
    // Check for returning pointer to local stack array
    // Pattern: return local_array; where local_array is declared in function

    // Get the return value - must be a SINGLE direct identifier, not part of an expression
    // We want to match "return array_name;" but not "return expr" or "return func()" or "return;"

    // Count meaningful children (non-punctuation)
    let meaningful_children: Vec<Node> = (0..node.child_count())
        .filter_map(|i| node.child(i))
        .filter(|child| {
            let kind = child.kind();
            kind != "return" && kind != ";" // Skip keywords and punctuation
        })
        .collect();

    // Must have exactly one meaningful child, and it must be an identifier
    if meaningful_children.len() != 1 || meaningful_children[0].kind() != "identifier" {
        return None;
    }

    let return_node = meaningful_children[0];
    let return_var = &source[return_node.start_byte()..return_node.end_byte()];

    // Additional safety: ignore common non-array identifiers
    if return_var == "NULL" || return_var.parse::<i32>().is_ok() {
        return None;
    }

    // Find the containing function
    let function_node = find_containing_function(node)?;

    // Search for local array declaration with this name
    let function_text = &source[function_node.start_byte()..function_node.end_byte()];

    // Look for pattern: type name[size] where name matches return_var
    // Need to check for word boundaries to avoid false positives like "size" matching "s<i>ze"
    let array_pattern = format!("{}[", return_var);

    if !function_text.contains(&array_pattern) {
        return None;
    }

    // Make sure it's not a parameter (parameters are before the opening brace)
    let body_start = function_text.find('{')?;
    let params_section = &function_text[..body_start];

    // If the array is in the parameters section, it's not a local array
    if params_section.contains(&array_pattern) {
        return None;
    }

    // Additionally, check that this is actually a declaration in the function body
    // Look for pattern "type varname[" to confirm it's a local array declaration
    let body_section = &function_text[body_start..];

    // Check for common array declaration patterns
    let type_keywords = [
        "int", "char", "float", "double", "long", "short", "unsigned", "signed", "size_t",
        "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    ];
    let has_array_declaration = type_keywords.iter().any(|&type_kw| {
        let decl_pattern = format!("{} {}", type_kw, array_pattern);
        body_section.contains(&decl_pattern)
            || body_section.contains(&format!(
                "{} *{}",
                type_kw,
                array_pattern.trim_end_matches('[')
            ))
    });

    if !has_array_declaration {
        return None;
    }

    // It's a local array being returned
    let line = source[..return_node.start_byte()]
        .chars()
        .filter(|&c| c == '\n')
        .count()
        + 1;
    let column = source[..return_node.start_byte()]
        .lines()
        .last()
        .map(|l| l.len())
        .unwrap_or(0)
        + 1;

    Some(RuleViolation {
        rule_id: "ARR00-C".to_string(),
        severity: Severity::Critical,
        message: format!(
            "Returning pointer to local array '{}' which will be destroyed when function returns, creating a dangling pointer.",
            return_var
        ),
        file_path: String::new(),
        line,
        column,
        suggestion: Some("Consider allocating the array dynamically (malloc/calloc), declaring it as static, or passing a buffer as a parameter.".to_string()),
        ..Default::default()
    })
}

fn check_pointer_arithmetic(node: &Node, source: &str) -> Option<RuleViolation> {
    // Check for pointer arithmetic that obviously exceeds array bounds
    // Pattern: ptr = arr + offset  where offset > array_size

    // binary_expression nodes have "left", "operator", and "right" fields
    let operator_node = node.child_by_field_name("operator")?;
    let operator = &source[operator_node.start_byte()..operator_node.end_byte()];

    // Only check addition (+ creates a pointer offset)
    if operator != "+" {
        return None;
    }

    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;

    // Right side should be a number literal (constant offset)
    if right.kind() != "number_literal" {
        return None;
    }

    // Get the array name and offset
    let array_name = &source[left.start_byte()..left.end_byte()];
    let offset_text = &source[right.start_byte()..right.end_byte()];

    // Parse the offset as a number
    let offset: usize = match offset_text.parse() {
        Ok(n) => n,
        Err(_) => return None, // Not a constant offset
    };

    // Find the array declaration in the function body to get its size
    let function_node = find_containing_function(node)?;

    // Find the compound_statement (function body) within the function_definition
    let mut body_start = function_node.start_byte();
    for i in 0..function_node.child_count() {
        if let Some(child) = function_node.child(i) {
            if child.kind() == "compound_statement" {
                // Skip the opening brace '{'
                body_start = child.start_byte() + 1;
                break;
            }
        }
    }

    let ptr_position = node.start_byte();

    // Ensure body_start is before ptr_position
    // If not, the pointer usage is before the function body (e.g., in parameters)
    if body_start > ptr_position {
        return None;
    }

    let preceding_text = &source[body_start..ptr_position];

    // Look for array declaration: type array_name[SIZE]
    if let Some(array_size) = find_array_size(array_name, preceding_text) {
        // Check if offset exceeds the array size
        // Note: arr + size (one past the end) is technically allowed but shouldn't be dereferenced
        if offset > array_size {
            let start_point = node.start_position();
            return Some(RuleViolation {
                rule_id: "ARR00-C".to_string(),
                severity: Severity::High,
                message: format!(
                    "Pointer arithmetic '{}' goes {} elements past the end of array '{}[{}]'. This exceeds array bounds.",
                    &source[node.start_byte()..node.end_byte()],
                    offset - array_size,
                    array_name,
                    array_size
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some(format!(
                    "Ensure pointer arithmetic stays within array bounds (0 to {})",
                    array_size
                )),
            ..Default::default()
            });
        }
    }

    None
}

fn check_pointer_subtraction(node: &Node, source: &str) -> Option<RuleViolation> {
    // Check for pointer subtraction between pointers to different arrays
    // Pattern: p1 - p2 where p1 and p2 point to different array objects
    // This is undefined behavior in C

    let operator_node = node.child_by_field_name("operator")?;
    let operator = &source[operator_node.start_byte()..operator_node.end_byte()];

    // Only check subtraction
    if operator != "-" {
        return None;
    }

    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;

    // Both sides should be identifiers (pointers/variables)
    if left.kind() != "identifier" || right.kind() != "identifier" {
        return None;
    }

    let left_name = &source[left.start_byte()..left.end_byte()];
    let right_name = &source[right.start_byte()..right.end_byte()];

    // If they're the same variable, it's fine (p - p = 0)
    if left_name == right_name {
        return None;
    }

    // Find the containing function to look up pointer origins
    let function_node = find_containing_function(node)?;
    let function_start = function_node.start_byte();
    let subtraction_position = node.start_byte();
    let preceding_text = &source[function_start..subtraction_position];

    // Try to determine what arrays these pointers point to
    // Pattern: int *p1 = &arr1[...]; or int *p1 = arr1 + ...;
    let left_array = find_pointer_source_array(left_name, preceding_text);
    let right_array = find_pointer_source_array(right_name, preceding_text);

    // If we can determine both source arrays and they're different, flag it
    if let (Some(left_arr), Some(right_arr)) = (left_array, right_array) {
        if left_arr != right_arr {
            let start_point = node.start_position();
            return Some(RuleViolation {
                rule_id: "ARR00-C".to_string(),
                severity: Severity::Critical,
                message: format!(
                    "Subtracting pointers from different arrays ('{}' from '{}' and '{}' from '{}'). Pointer subtraction is only defined for pointers within the same array object.",
                    left_name,
                    left_arr,
                    right_name,
                    right_arr
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some(
                    "Only subtract pointers that point to elements within the same array object.".to_string()
                ),
            ..Default::default()
            });
        }
    }

    None
}

fn find_pointer_source_array(ptr_name: &str, preceding_text: &str) -> Option<String> {
    find_pointer_source_array_recursive(ptr_name, preceding_text, 0)
}

fn find_pointer_source_array_recursive(
    ptr_name: &str,
    preceding_text: &str,
    depth: usize,
) -> Option<String> {
    // Limit recursion to avoid infinite loops with circular assignments
    if depth > 5 {
        return None;
    }

    // Try to find what array this pointer points to
    // Patterns to look for:
    // 1. int *p = &arr[...];
    // 2. int *p = arr + ...;
    // 3. int *p = arr;

    // Look for the pointer declaration/assignment
    let patterns = [
        format!("{} = &", ptr_name),  // p = &arr[...]
        format!("{} = ", ptr_name),   // p = arr or p = arr + ...
        format!("*{} = &", ptr_name), // int *p = &arr[...]
        format!("*{} = ", ptr_name),  // int *p = arr
    ];

    for pattern in &patterns {
        if let Some(pos) = preceding_text.rfind(pattern) {
            // Get text after the = sign
            let after_eq = &preceding_text[pos + pattern.len()..];

            // Skip whitespace
            let after_eq = after_eq.trim_start();

            // If it starts with &, skip it
            let after_eq = if let Some(stripped) = after_eq.strip_prefix('&') {
                stripped
            } else {
                after_eq
            };

            // Extract the source name (up to '[', '+', ',', ';', or whitespace)
            // Use char_indices() to get byte offsets (not char indices) for safe slicing.
            let mut end_pos = 0;
            for (i, c) in after_eq.char_indices() {
                if c == '[' || c == '+' || c == ',' || c == ';' || c.is_whitespace() || c == ')' {
                    end_pos = i;
                    break;
                }
            }

            if end_pos > 0 {
                let source_name = &after_eq[..end_pos];
                if !source_name.is_empty()
                    && source_name.chars().all(|c| c.is_alphanumeric() || c == '_')
                {
                    // Recursively resolve: if source is itself a pointer assigned
                    // from another variable, follow the chain to the ultimate base.
                    // e.g., end = pos + N; pos = buf; → end's base is buf
                    if let Some(resolved) = find_pointer_source_array_recursive(
                        source_name,
                        &preceding_text[..pos],
                        depth + 1,
                    ) {
                        return Some(resolved);
                    }
                    return Some(source_name.to_string());
                }
            }
        }
    }

    None
}

/// Resolve an array's declared element count from its AST declaration.
///
/// Finds the `array_declarator` that declares `var_name` in the nearest block
/// scope enclosing `use_node`, then computes its size as
/// `max(evaluated-size-expression, initializer-element-count)`.
///
/// Returns `None` when the bound cannot be determined safely:
///   - the variable has no array declaration in scope,
///   - the explicit size expression is a non-constant we cannot evaluate
///     (e.g. a runtime expression or unknown macro), or
///   - a designated initializer is present without an evaluable explicit size.
///
/// Returning `None` suppresses the out-of-bounds check — the conservative,
/// false-positive-avoiding choice when the true bound is unknown.
fn resolve_declared_array_size(
    use_node: &Node,
    var_name: &str,
    source: &str,
    macros: &MacroConstantMap,
) -> Option<usize> {
    let arr_decl = find_array_declarator_in_scope(use_node, var_name, source)?;

    // Evaluate the explicit dimension expression, if any.
    let declared = match arr_decl.child_by_field_name("size") {
        Some(size_expr) => match try_evaluate_expr(&size_expr, source, macros) {
            Some(v) if v > 0 => Some(v as usize),
            // Size expression present but not a positive constant we can
            // evaluate -> bound unknown, do not flag.
            _ => return None,
        },
        // No explicit size (`arr[] = {...}`); rely on the initializer count.
        None => None,
    };

    // Count top-level initializer elements, if the declarator is initialized.
    let init_count = arr_decl
        .parent()
        .filter(|p| p.kind() == "init_declarator")
        .and_then(|p| p.child_by_field_name("value"))
        .filter(|v| v.kind() == "initializer_list")
        .and_then(|v| count_initializer_elements(&v));

    match (declared, init_count) {
        (Some(d), Some(c)) => Some(d.max(c)),
        (Some(d), None) => Some(d),
        (None, Some(c)) => Some(c),
        (None, None) => None,
    }
}

/// Find the `array_declarator` that declares `var_name` and is visible at
/// `use_node`, honoring C block scoping: walk enclosing scopes innermost-first
/// so a block-local `tmp[4]` shadows a `tmp[3]` declared in a sibling block.
fn find_array_declarator_in_scope<'a>(
    use_node: &Node<'a>,
    var_name: &str,
    source: &str,
) -> Option<Node<'a>> {
    let before = use_node.start_byte();
    let mut scope = use_node.parent();
    while let Some(s) = scope {
        if let Some(found) = scan_block_declarators(&s, var_name, source, before) {
            return Some(found);
        }
        scope = s.parent();
    }
    None
}

/// Search one scope for an `array_declarator` of `var_name` declared textually
/// before byte offset `before`, without crossing into nested block scopes
/// (their declarations are not visible here).
fn scan_block_declarators<'a>(
    scope: &Node<'a>,
    var_name: &str,
    source: &str,
    before: usize,
) -> Option<Node<'a>> {
    for i in 0..scope.child_count() {
        if let Some(child) = scope.child(i) {
            // A nested block / function body is a separate scope — skip it.
            if matches!(child.kind(), "compound_statement" | "function_definition") {
                continue;
            }
            if child.kind() == "array_declarator"
                && child.start_byte() < before
                && declarator_names(&child, source) == var_name
            {
                return Some(child);
            }
            if let Some(found) = scan_block_declarators(&child, var_name, source, before) {
                return Some(found);
            }
        }
    }
    None
}

/// Count top-level elements in an `initializer_list`.
///
/// Returns `None` if the list uses designated initializers (e.g. `[3] = x`),
/// where the element count does not bound the array size.
fn count_initializer_elements(list: &Node) -> Option<usize> {
    let mut count = 0;
    for i in 0..list.child_count() {
        if let Some(child) = list.child(i) {
            match child.kind() {
                "{" | "}" | "," | "comment" => {}
                // Designated initializer (`[idx] = v` or `.field = v`): the
                // element count does not bound the array size -> give up.
                "initializer_pair" => return None,
                _ => count += 1,
            }
        }
    }
    if count > 0 {
        Some(count)
    } else {
        None
    }
}

fn find_array_size(array_name: &str, preceding_text: &str) -> Option<usize> {
    // Look for array declaration patterns: type array_name[SIZE] = ...
    // Examples: int arr[5], char buf[100]
    // Need to distinguish declarations from subscript usage

    // Search for all occurrences of "array_name[" pattern
    let pattern = format!("{}[", array_name);
    let mut search_start = 0;

    while let Some(pos) = preceding_text[search_start..].find(&pattern) {
        let absolute_pos = search_start + pos;
        let after_name = &preceding_text[absolute_pos..];

        if let Some(bracket_start) = after_name.find('[') {
            if let Some(bracket_end) = after_name.find(']') {
                if bracket_end > bracket_start {
                    let size_text = after_name[bracket_start + 1..bracket_end].trim();

                    // Try to parse as a number
                    if let Ok(size) = size_text.parse::<usize>() {
                        // Check if this looks like a declaration, not a subscript usage
                        // Look backwards for type keywords
                        let before_name = &preceding_text[..absolute_pos];
                        let type_keywords = [
                            "int", "char", "float", "double", "long", "short", "unsigned",
                            "signed", "size_t", "void", "struct",
                        ];

                        // Look at the last ~50 characters before the array name
                        let check_range = if before_name.len() > 50 {
                            &before_name[before_name.len() - 50..]
                        } else {
                            before_name
                        };

                        // If we find a type keyword nearby, it's likely a declaration
                        if type_keywords.iter().any(|&kw| check_range.contains(kw)) {
                            return Some(size);
                        }
                    }
                }
            }
        }

        search_start = absolute_pos + pattern.len();
    }

    None
}

// ============================================================================
// Array Comparison Checks
// ============================================================================

fn check_array_comparison(node: &Node, source: &str) -> Option<RuleViolation> {
    // Check for array comparisons using == or !=
    let operator = node.child_by_field_name("operator")?;
    let op_text = &source[operator.start_byte()..operator.end_byte()];

    if op_text != "==" && op_text != "!=" {
        return None;
    }

    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;

    // Get the text of both sides
    let left_text = &source[left.start_byte()..left.end_byte()];
    let right_text = &source[right.start_byte()..right.end_byte()];

    // Don't flag comparisons with NULL (null checks are valid)
    if left_text == "NULL" || right_text == "NULL" {
        return None;
    }

    // Check if BOTH sides are arrays (comparing two arrays)
    // Comparing array with NULL or other values is fine
    if is_array_identifier(&left, source) && is_array_identifier(&right, source) {
        let start_point = node.start_position();
        return Some(RuleViolation {
            rule_id: "ARR00-C".to_string(),
            severity: Severity::Medium,
            message: "Comparing arrays with == or != compares addresses, not contents".to_string(),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some("Use memcmp() or strcmp() to compare array contents".to_string()),
            ..Default::default()
        });
    }

    None
}

// ============================================================================
// AST Traversal Helpers
// ============================================================================
// Function Navigation and Parameter Extraction
// Now imported from ast_utils:
// - find_containing_function()
// - get_function_parameters()
// - find_identifier_in_declarator()
// - is_array_parameter_type()
// ============================================================================

// Type and Node Classification Helpers
// ============================================================================

fn is_array_identifier(node: &Node, source: &str) -> bool {
    // Check if identifier was declared as a true array (type name[SIZE]),
    // NOT a pointer (type *name) that happens to be subscripted.

    if node.kind() != "identifier" || is_function_call_name(node) {
        return false;
    }

    let identifier_name = &source[node.start_byte()..node.end_byte()];

    // Walk up to the containing function and search its body for a declaration
    // of this identifier that uses array_declarator syntax.
    if let Some(function_node) = find_containing_function(node) {
        return has_array_declaration(&function_node, identifier_name, source);
    }

    false
}

/// Check if a variable is declared as an array (with `[]` in the declarator)
/// anywhere in the given scope node. Returns false for pointer declarations.
fn has_array_declaration(scope: &Node, var_name: &str, source: &str) -> bool {
    match scope.kind() {
        "declaration"
            // Check if this declaration declares var_name as an array
            if declaration_is_array_for(scope, var_name, source) => {
                return true;
            }
        "parameter_declaration"
            // Array parameters (e.g., `int arr[]`) — check for array_declarator
            if param_is_array_for(scope, var_name, source) => {
                return true;
            }
        _ => {}
    }

    for i in 0..scope.child_count() {
        if let Some(child) = scope.child(i) {
            if has_array_declaration(&child, var_name, source) {
                return true;
            }
        }
    }
    false
}

/// Check if a declaration node declares `var_name` as an array (not a pointer).
fn declaration_is_array_for(decl: &Node, var_name: &str, source: &str) -> bool {
    for i in 0..decl.child_count() {
        if let Some(child) = decl.child(i) {
            // Direct array_declarator: `int data[10]`
            if child.kind() == "array_declarator" {
                if declarator_names(&child, source) == var_name {
                    return true;
                }
            }
            // init_declarator wrapping array_declarator: `int data[10] = {0}`
            if child.kind() == "init_declarator" {
                for j in 0..child.child_count() {
                    if let Some(gc) = child.child(j) {
                        if gc.kind() == "array_declarator" {
                            if declarator_names(&gc, source) == var_name {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

/// Check if a parameter_declaration declares `var_name` as an array.
fn param_is_array_for(param: &Node, var_name: &str, source: &str) -> bool {
    for i in 0..param.child_count() {
        if let Some(child) = param.child(i) {
            if child.kind() == "array_declarator" {
                if declarator_names(&child, source) == var_name {
                    return true;
                }
            }
        }
    }
    false
}

/// Extract the base identifier name from a declarator (which may be nested).
fn declarator_names<'a>(node: &Node, source: &'a str) -> &'a str {
    // array_declarator's first child is either an identifier or another declarator
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "identifier" {
                return &source[child.start_byte()..child.end_byte()];
            }
            if child.kind() == "array_declarator" || child.kind() == "pointer_declarator" {
                return declarator_names(&child, source);
            }
        }
    }
    ""
}

fn is_subscript(node: &Node) -> bool {
    node.kind() == "subscript_expression"
}

fn is_function_call_name(node: &Node) -> bool {
    // Check if this identifier is the function part of a call expression
    if let Some(parent) = node.parent() {
        parent.kind() == "call_expression" && parent.child_by_field_name("function") == Some(*node)
    } else {
        false
    }
}
