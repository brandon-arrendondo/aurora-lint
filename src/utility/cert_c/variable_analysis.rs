//! Variable Analysis Utilities for CERT C Rules
//!
//! This module provides common functions for analyzing variable usage patterns,
//! including validation detection, initialization tracking, and input source detection.

/// Check if a variable was populated from user input (scanf, fscanf, fgets, etc.)
///
/// # Arguments
/// * `var_name` - The name of the variable to check
/// * `preceding_text` - The source code text before the current location
///
/// # Returns
/// `true` if the variable appears to be populated from user input
///
/// # Examples
/// ```
/// use aurora_lint::utility::cert_c::variable_analysis::is_user_input_variable;
/// let code = r#"int count; scanf("%d", &count);"#;
/// assert!(is_user_input_variable("count", code));
/// ```
pub fn is_user_input_variable(var_name: &str, preceding_text: &str) -> bool {
    // Check if variable was populated by scanf, fscanf, fgets, or other input functions
    let input_patterns = [
        format!("scanf(\"%d\", &{})", var_name),
        format!("scanf(\"%d\",&{})", var_name),
        format!("scanf ( \"%d\" , &{} )", var_name),
        format!("fscanf(stdin, \"%d\", &{})", var_name),
        format!("scanf(\"%u\", &{})", var_name),
    ];

    // Simple check: does scanf read into this variable?
    input_patterns
        .iter()
        .any(|pattern| preceding_text.contains(pattern))
        || preceding_text.contains("scanf") && preceding_text.contains(&format!("&{}", var_name))
}

/// Check if a variable has validation between input and usage
///
/// # Arguments
/// * `var_name` - The name of the variable to check
/// * `preceding_text` - The source code text before the loop
/// * `loop_pos` - The byte position of the loop in the full source
/// * `source` - The complete source code
///
/// # Returns
/// `true` if validation is found between the input and the loop
///
/// # Examples
/// ```
/// use aurora_lint::utility::cert_c::variable_analysis::has_validation_before_loop;
/// let code = r#"scanf("%d", &count); if (count > MAX) { exit(1); } for (int i = 0; i < count; i++)"#;
/// assert!(has_validation_before_loop("count", code, 50, code));
/// ```
pub fn has_validation_before_loop(
    var_name: &str,
    preceding_text: &str,
    _loop_pos: usize,
    _source: &str,
) -> bool {
    // Check if there's validation of var_name between scanf and the loop
    // Look for patterns like: if (count > MAX) or if (count < 0)

    // Find where scanf populated the variable
    if let Some(scanf_pos) = preceding_text.rfind("scanf") {
        let between_scanf_and_loop = &preceding_text[scanf_pos..];

        // Look for validation patterns
        let validation_patterns = [
            format!("if ({} >", var_name),
            format!("if ({} <", var_name),
            format!("if ({} >=", var_name),
            format!("if ({} <=", var_name),
            format!("if (0 >{}", var_name),
            format!("if (0 <{}", var_name),
        ];

        return validation_patterns
            .iter()
            .any(|p| between_scanf_and_loop.contains(p));
    }

    false
}

/// Check if a variable is declared but never initialized
///
/// # Arguments
/// * `var_name` - The name of the variable to check
/// * `preceding_text` - The source code text before the current location
///
/// # Returns
/// `true` if the variable is declared but not initialized
///
/// # Examples
/// ```
/// use aurora_lint::utility::cert_c::variable_analysis::is_uninitialized_variable;
/// let code = "int size; for (int i = 0; i < size; i++)";
/// assert!(is_uninitialized_variable("size", code));
///
/// let code2 = "int size = 10; for (int i = 0; i < size; i++)";
/// assert!(!is_uninitialized_variable("size", code2));
/// ```
pub fn is_uninitialized_variable(var_name: &str, preceding_text: &str) -> bool {
    // Check if variable is declared but never initialized
    // Look for patterns like: "int size;" without "size =" before the loop

    // First, check if this is a constant (all uppercase or #define) - constants are always initialized
    if var_name
        .chars()
        .all(|c| c.is_uppercase() || c == '_' || c.is_numeric())
    {
        return false; // Likely a constant/macro
    }

    // Check if variable is declared (simple heuristic)
    let declaration_patterns = [
        format!("int {};", var_name),
        format!("int {} ;", var_name),
        format!("size_t {};", var_name),
        format!("unsigned {}", var_name),
        format!("long {}", var_name),
    ];

    let is_declared = declaration_patterns
        .iter()
        .any(|p| preceding_text.contains(p))
        || (preceding_text.contains("int")
            && preceding_text.contains(var_name)
            && !preceding_text.contains(&format!("{}[", var_name))); // Not an array declaration

    if !is_declared {
        return false;
    }

    // Check if it's been assigned a value
    let assignment_patterns = [
        format!("{} =", var_name),
        format!("{}=", var_name),
        format!("&{}", var_name), // scanf with &var means it's initialized by input
    ];

    let is_initialized = assignment_patterns
        .iter()
        .any(|p| preceding_text.contains(p));

    // Variable is uninitialized if declared but not initialized
    !is_initialized
}

/// Check if a variable has bounds validation before usage
///
/// # Arguments
/// * `var_name` - The name of the variable to check
/// * `preceding_text` - The source code text before the current location
///
/// # Returns
/// `true` if bounds validation is detected
///
/// # Examples
/// ```
/// use aurora_lint::utility::cert_c::variable_analysis::has_bounds_validation;
/// let code = "if (index < 0 || index >= size) { return; } arr[index] = val;";
/// assert!(has_bounds_validation("index", code));
/// ```
pub fn has_bounds_validation(var_name: &str, preceding_text: &str) -> bool {
    // Look for validation patterns like:
    // if (index < 0 || index >= size)
    // if (index < size)
    // if (index >= 0 && index < size)

    // Simple heuristic: look for the variable in a comparison context
    // This is not perfect but catches common validation patterns
    let patterns = [
        format!("{} <", var_name),
        format!("{} <=", var_name),
        format!("{} >", var_name),
        format!("{} >=", var_name),
        format!("< {}", var_name),
        format!("<= {}", var_name),
        format!("> {}", var_name),
        format!(">= {}", var_name),
    ];

    // Look for if statements containing these patterns
    for pattern in &patterns {
        if preceding_text.contains("if") && preceding_text.contains(pattern) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_user_input_variable() {
        let code = r#"int count; scanf("%d", &count);"#;
        assert!(is_user_input_variable("count", code));

        let code2 = "int count = 10;";
        assert!(!is_user_input_variable("count", code2));
    }

    #[test]
    fn test_has_validation_before_loop() {
        let code = r#"scanf("%d", &count); if (count > 100) { exit(1); } for"#;
        assert!(has_validation_before_loop("count", code, 50, code));

        let code2 = r#"scanf("%d", &count); for"#;
        assert!(!has_validation_before_loop("count", code2, 30, code2));
    }

    #[test]
    fn test_is_uninitialized_variable() {
        let code = "int size; for (int i = 0; i < size; i++)";
        assert!(is_uninitialized_variable("size", code));

        let code2 = "int size = 10; for (int i = 0; i < size; i++)";
        assert!(!is_uninitialized_variable("size", code2));

        let code3 = "int MAX_SIZE; // constant";
        assert!(!is_uninitialized_variable("MAX_SIZE", code3));
    }

    #[test]
    fn test_has_bounds_validation() {
        let code = "if (index < size) { arr[index] = val; }";
        assert!(has_bounds_validation("index", code));

        let code2 = "arr[index] = val;";
        assert!(!has_bounds_validation("index", code2));
    }
}
