//! Size Analysis Utilities for CERT C Rules
//!
//! This module provides common functions for analyzing array sizes, allocation sizes,
//! element sizes, and string literal lengths. These are used for bounds checking and
//! buffer overflow detection.

use super::ast_utils::find_containing_function;
use crate::analyze::buffer_size::sizeof_type_bytes;
use tree_sitter::Node;

/// Determine the element size of an array based on its type declaration
///
/// # Arguments
/// * `var_name` - The name of the array variable
/// * `preceding_text` - The source code text before the current location
///
/// # Returns
/// The size in bytes of the array element type (defaults to 4 for int)
///
/// # Examples
/// ```
/// use aurora_lint::utility::cert_c::size_analysis::find_element_size;
/// // Works when declaration is found before usage point
/// let code = "int numbers[10];";
/// assert_eq!(find_element_size("numbers", code), 4);
///
/// let code2 = "char buffer[100];";
/// assert_eq!(find_element_size("buffer", code2), 1);
/// ```
pub fn find_element_size(var_name: &str, preceding_text: &str) -> usize {
    // Try to determine the element type and return its size
    // Pattern: type var_name[...]

    // Candidate type keywords a declaration might end with, immediately
    // before `var_name[`. Byte sizes themselves come from the shared
    // canonical table (task 511) rather than a rule-local copy.
    let type_names = [
        "char",
        "short",
        "int",
        "long",
        "float",
        "double",
        "unsigned char",
        "unsigned short",
        "unsigned int",
        "unsigned long",
        "signed char",
        "signed short",
        "signed int",
        "signed long",
    ];

    let pattern = format!("{}[", var_name);

    if let Some(pos) = preceding_text.rfind(&pattern) {
        // Look backwards from the array name to find the type
        let before_array = &preceding_text[..pos];

        // Search for type keywords
        for type_name in &type_names {
            if before_array.ends_with(type_name)
                || before_array.ends_with(&format!("{} ", type_name))
            {
                if let Some(size) = sizeof_type_bytes(type_name) {
                    return size;
                }
            }
        }
    }

    // Default to int (4 bytes) if we can't determine the type
    4
}

/// Find the length of a string literal assigned to a variable
///
/// # Arguments
/// * `var_name` - The name of the variable
/// * `node` - The current AST node
/// * `source` - The complete source code
///
/// # Returns
/// `Some(length)` if a string literal is found, `None` otherwise
///
/// # Examples
/// ```no_run
/// use aurora_lint::utility::cert_c::size_analysis::find_string_literal_length;
/// use tree_sitter::Node;
/// // When checking the strcpy call with msg:
/// // let node: Node = /* get from parsed AST */;
/// // let code = r#"char *msg = "hello"; strcpy(dest, msg);"#;
/// // assert_eq!(find_string_literal_length("msg", &node, code), Some(5));
/// ```
pub fn find_string_literal_length(var_name: &str, node: &Node, source: &str) -> Option<usize> {
    // Find the variable declaration and extract string literal length
    // Pattern: char *var = "literal"; or char var[] = "literal";

    let function_node = find_containing_function(node)?;
    let function_start = function_node.start_byte();
    let call_position = node.start_byte();
    let preceding_text = &source[function_start..call_position];

    // Look for variable initialization with string literal
    // Simple pattern matching: var_name = "..."
    let pattern = format!("{} =", var_name);
    if let Some(init_pos) = preceding_text.rfind(&pattern) {
        // Find the string literal after the =
        let after_eq = &preceding_text[init_pos + pattern.len()..];

        // Find the opening quote
        if let Some(quote_start) = after_eq.find('"') {
            // Find the closing quote (accounting for escaped quotes)
            let mut i = quote_start + 1;
            let chars: Vec<char> = after_eq.chars().collect();
            while i < chars.len() {
                if chars[i] == '"' && (i == 0 || chars[i - 1] != '\\') {
                    // Found closing quote
                    let literal = &after_eq[quote_start + 1..i];
                    return Some(literal.len());
                }
                i += 1;
            }
        }
    }

    None
}

/// Find the size of a malloc/realloc allocation for a pointer
///
/// # Arguments
/// * `ptr_name` - The name of the pointer variable
/// * `preceding_text` - The source code text before the current location
///
/// # Returns
/// `Some(count)` where count is the number of elements allocated, `None` if not found
///
/// # Examples
/// ```
/// use aurora_lint::utility::cert_c::size_analysis::find_allocation_size;
/// let code = "int *arr = malloc(10 * sizeof(int)); for (i = 0; i < 15; i++)";
/// assert_eq!(find_allocation_size("arr", code), Some(10));
///
/// let code2 = "char *buf = realloc(buf, 5 * sizeof(char)); buf[6] = 'a';";
/// assert_eq!(find_allocation_size("buf", code2), Some(5));
/// ```
pub fn find_allocation_size(ptr_name: &str, preceding_text: &str) -> Option<usize> {
    // Look for the most recent malloc/realloc call for this pointer
    // Patterns: ptr = malloc(N * sizeof(...))  or  ptr = realloc(ptr, N * sizeof(...))
    // Also handles: type *ptr = malloc(...) declarations

    // Search for realloc first (more recent), then malloc
    // Try both "ptr = malloc" and "*ptr = malloc" patterns
    let realloc_pattern = format!("{} = realloc", ptr_name);
    let malloc_pattern = format!("{} = malloc", ptr_name);
    let ptr_realloc_pattern = format!("*{} = realloc", ptr_name);
    let ptr_malloc_pattern = format!("*{} = malloc", ptr_name);

    let realloc_pos = preceding_text
        .rfind(&realloc_pattern)
        .or_else(|| preceding_text.rfind(&ptr_realloc_pattern));
    let malloc_pos = preceding_text
        .rfind(&malloc_pattern)
        .or_else(|| preceding_text.rfind(&ptr_malloc_pattern));

    // Use whichever is more recent (appears later in the text)
    let (_pattern, pos) = match (malloc_pos, realloc_pos) {
        (Some(m), Some(r)) => {
            if r > m {
                ("realloc", r)
            } else {
                ("malloc", m)
            }
        }
        (Some(m), None) => ("malloc", m),
        (None, Some(r)) => ("realloc", r),
        (None, None) => return None,
    };

    // Extract the allocation size from the call
    // Look for pattern: malloc(N * sizeof(...)) or malloc(N*sizeof(...))
    // For realloc: realloc(ptr, N * sizeof(...))
    let after_call = &preceding_text[pos..];
    if let Some(paren_start) = after_call.find('(') {
        if let Some(paren_end) = after_call.find(')') {
            let mut args = &after_call[paren_start + 1..paren_end];

            // For realloc, skip the first argument (the pointer)
            if after_call.contains("realloc") {
                if let Some(comma_pos) = args.find(',') {
                    args = args[comma_pos + 1..].trim();
                }
            }

            // Try to extract N from "N * sizeof(...)" or "N*sizeof(...)"
            if args.contains("sizeof") {
                // Split by * and take the first part (should be N)
                let parts: Vec<&str> = args.split('*').collect();
                if let Some(size_str) = parts.first() {
                    let size_str = size_str.trim();
                    if let Ok(size) = size_str.parse::<usize>() {
                        return Some(size);
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_element_size() {
        let code = "int numbers[10];";
        assert_eq!(find_element_size("numbers", code), 4);

        let code2 = "char buffer[100];";
        assert_eq!(find_element_size("buffer", code2), 1);

        let code3 = "double values[5];";
        assert_eq!(find_element_size("values", code3), 8);

        let code4 = "unknown_type data[20];";
        assert_eq!(find_element_size("data", code4), 4); // defaults to int
    }

    #[test]
    fn test_find_allocation_size() {
        let code = "int *arr = malloc(10 * sizeof(int));";
        assert_eq!(find_allocation_size("arr", code), Some(10));

        let code2 = "char *buf = realloc(buf, 5 * sizeof(char));";
        assert_eq!(find_allocation_size("buf", code2), Some(5));

        let code3 = "ptr = malloc(100*sizeof(int));";
        assert_eq!(find_allocation_size("ptr", code3), Some(100));

        let code4 = "int *p;"; // No allocation
        assert_eq!(find_allocation_size("p", code4), None);
    }

    #[test]
    fn test_find_allocation_size_realloc_priority() {
        // realloc should take priority over earlier malloc
        let code = "ptr = malloc(5 * sizeof(int)); ptr = realloc(ptr, 10 * sizeof(int));";
        assert_eq!(find_allocation_size("ptr", code), Some(10));
    }
}
