//! Shared buffer-size analysis API.
//!
//! Buffer-size reasoning ("how many elements / bytes does this allocation
//! hold?") was historically duplicated across rules: ARR30-C carried an
//! AST-driven [`BufferInfo`]/[`BufferSize`] model plus a family of
//! size-expression parsers, while STR31-C re-implemented overlapping
//! malloc/calloc/alloca arithmetic with its own inline regex blocks. This
//! module is the single home for that machinery so future false-positive
//! work (tasks 143/144/145) builds on one API instead of accreting into the
//! individual rule files.
//!
//! The parsers here are pure functions over the textual argument of an
//! allocation call (e.g. the `"5 * sizeof(int)"` inside `malloc(...)`). They
//! make the same fixed-width assumptions ARR30-C always has (typical 64-bit
//! Linux: `int` = 4, pointer = 8, …); see [`extract_sizeof_value`].

/// Information about a buffer (array or dynamically allocated memory).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BufferInfo {
    /// The buffer's variable name.
    pub name: String,
    /// The buffer's size, in whatever form it could be determined.
    pub size: BufferSize,
    /// Textual element type (e.g. `"int"`).
    pub element_type: String,
    /// Line the buffer was declared/allocated on.
    pub allocation_line: usize,
    /// Raw allocation byte count (for byte-level comparisons).
    pub alloc_bytes: Option<usize>,
}

/// Represents the size of a buffer.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum BufferSize {
    /// `char arr[10]`
    Static(usize),
    /// `malloc(10 * sizeof(int))` — element count
    DynamicCalculated(usize),
    /// `malloc(size)` — variable expression
    Dynamic(String),
    /// VLA: `int arr[n]` — symbolic size
    Symbolic(String),
    /// Size could not be determined.
    Unknown,
}

/// Evaluate a two-operand `A op B` arithmetic expression where `op` is `+`
/// or `-`. Returns `None` for anything more complex (more than two operands,
/// multiplication, leading minus, non-numeric operands).
///
/// Mirrors ARR30-C's historical `evaluate_simple_arithmetic`.
pub fn evaluate_simple_arithmetic(expr: &str) -> Option<isize> {
    let expr = expr.trim();

    // Handle "A - B"
    if expr.contains('-') && !expr.starts_with('-') {
        let parts: Vec<&str> = expr.split('-').collect();
        if parts.len() == 2 {
            let a: isize = parts[0].trim().parse().ok()?;
            let b: isize = parts[1].trim().parse().ok()?;
            return Some(a - b);
        }
    }

    // Handle "A + B"
    if expr.contains('+') {
        let parts: Vec<&str> = expr.split('+').collect();
        if parts.len() == 2 {
            let a: isize = parts[0].trim().parse().ok()?;
            let b: isize = parts[1].trim().parse().ok()?;
            return Some(a + b);
        }
    }

    None
}

/// Extract a non-negative numeric value from a size sub-expression, tolerating
/// surrounding parentheses and simple `A + B`/`A - B` arithmetic.
pub fn extract_numeric_value(s: &str) -> Option<usize> {
    let trimmed = s.trim();
    // Strip outer parentheses: "(10+1)" → "10+1"
    let inner = if trimmed.starts_with('(') && trimmed.ends_with(')') {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };
    // Try direct parse first
    if let Ok(v) = inner.parse() {
        return Some(v);
    }
    // Try evaluating simple arithmetic (e.g., "10+1")
    let result = evaluate_simple_arithmetic(inner)?;
    if result >= 0 {
        Some(result as usize)
    } else {
        None
    }
}

/// Resolve the byte size of a `sizeof(TYPE)` sub-expression using fixed-width
/// assumptions (typical 64-bit Linux). Returns `None` if `s` contains no
/// `sizeof`, and falls back to pointer size (8) for unrecognised types.
pub fn extract_sizeof_value(s: &str) -> Option<usize> {
    if !s.contains("sizeof") {
        return None;
    }

    // Common type sizes (assuming typical 64-bit Linux system)
    let type_sizes = [
        ("wchar_t", 4),
        ("int", 4),
        ("char", 1),
        ("short", 2),
        ("long", 8),
        ("float", 4),
        ("double", 8),
        ("void*", 8),
        ("int*", 8),
        ("char*", 8),
        ("wchar_t*", 8),
    ];

    for (type_name, size) in &type_sizes {
        if s.contains(type_name) {
            return Some(*size);
        }
    }

    // Default to pointer size if we can't determine
    Some(8)
}

/// Allocation function names whose first (or count) argument gives an
/// element-count buffer size. Includes the Juliet `ALLOCA` macro alias.
pub const ALLOC_FUNCTIONS: &[&str] =
    &["malloc", "calloc", "realloc", "alloca", "_alloca", "ALLOCA"];

/// Resolve the element-count buffer size of an allocation call from its
/// callee name and raw argument text. `calloc(n, sz)` uses the first argument;
/// every other allocator uses the whole argument expression. Returns `None`
/// when the size is not a compile-time constant element count.
pub fn alloc_call_element_count(func_name: &str, args_text: &str) -> Option<usize> {
    // calloc(nmemb, size): the element count is the first argument.
    let size_expr = if func_name == "calloc" {
        args_text.split(',').next().unwrap_or(args_text)
    } else {
        args_text
    };
    match calculate_malloc_size(size_expr)? {
        BufferSize::Static(n) | BufferSize::DynamicCalculated(n) => Some(n),
        _ => None,
    }
}

/// Calculate the element-count size from a malloc/calloc/realloc argument
/// expression. For `N * sizeof(T)` this returns the element count `N`, not
/// the byte total (see [`calculate_alloc_bytes`] for bytes).
pub fn calculate_malloc_size(malloc_args: &str) -> Option<BufferSize> {
    let trimmed = malloc_args.trim();

    // Pattern 1: Simple number - malloc(100)
    if let Some(size) = extract_numeric_value(trimmed) {
        return Some(BufferSize::DynamicCalculated(size));
    }

    // Pattern 2: COUNT * sizeof(TYPE) - malloc(5 * sizeof(int))
    // Store the COUNT (number of elements), not the byte size
    if trimmed.contains('*') && trimmed.contains("sizeof") {
        // Split only on the first '*' to handle cases like "3 * sizeof(int*)"
        if let Some(mult_pos) = trimmed.find('*') {
            let count_str = &trimmed[..mult_pos].trim();
            let sizeof_str = &trimmed[mult_pos + 1..].trim();

            let count = extract_numeric_value(count_str);
            let _sizeof_val = extract_sizeof_value(sizeof_str);

            if let Some(c) = count {
                // Store element count, not byte count
                return Some(BufferSize::DynamicCalculated(c));
            }
            // Count is a variable (e.g., data*sizeof(char)) — size is unknown
            // Do NOT fall through to pattern 3 which would misinterpret
            // "data*sizeof(char)" as sizeof(char)=1
            return Some(BufferSize::Dynamic(trimmed.to_string()));
        }
    }

    // Pattern 3: Just sizeof(TYPE) - malloc(sizeof(struct foo))
    if let Some(sizeof_val) = extract_sizeof_value(trimmed) {
        return Some(BufferSize::DynamicCalculated(sizeof_val));
    }

    // Pattern 4: Variable expression
    Some(BufferSize::Dynamic(trimmed.to_string()))
}

/// Calculate the raw byte count of a malloc/realloc allocation expression.
/// Unlike [`calculate_malloc_size`], `N * sizeof(T)` yields `N * sizeof(T)`
/// bytes rather than the element count.
pub fn calculate_alloc_bytes(malloc_args: &str) -> Option<usize> {
    let trimmed = malloc_args.trim();

    // Pattern 1: Simple number - malloc(100) → 100 bytes
    if let Some(size) = extract_numeric_value(trimmed) {
        return Some(size);
    }

    // Pattern 2: COUNT * sizeof(TYPE) - malloc(5 * sizeof(int)) → 5 * 4 = 20 bytes
    if trimmed.contains('*') && trimmed.contains("sizeof") {
        if let Some(mult_pos) = trimmed.find('*') {
            let count_str = trimmed[..mult_pos].trim();
            let sizeof_str = trimmed[mult_pos + 1..].trim();

            let count = extract_numeric_value(count_str);
            let sizeof_val = extract_sizeof_value(sizeof_str);

            if let (Some(c), Some(s)) = (count, sizeof_val) {
                return Some(c * s);
            }
        }
    }

    // Pattern 3: Just sizeof(TYPE) - malloc(sizeof(struct foo))
    if let Some(sizeof_val) = extract_sizeof_value(trimmed) {
        return Some(sizeof_val);
    }

    None
}

/// Parse a simple size expression: a bare `"49"` or an `N-M` subtraction such
/// as `"50-1"` / `"100-1"`. Returns `None` for anything more complex.
/// Subtraction uses `checked_sub`, so an underflow (`"1-5"`) yields `None`.
pub fn parse_simple_size_expr(expr: &str) -> Option<usize> {
    let expr = expr.trim();
    if let Ok(n) = expr.parse::<usize>() {
        return Some(n);
    }
    // N-M pattern (use rfind to handle potential negative results)
    if let Some(pos) = expr.rfind('-') {
        if pos > 0 {
            let left = expr[..pos].trim();
            let right = expr[pos + 1..].trim();
            if let (Ok(l), Ok(r)) = (left.parse::<usize>(), right.parse::<usize>()) {
                return l.checked_sub(r);
            }
        }
    }
    None
}

/// Line range `(start_row, end_row)` of the `function_definition` enclosing
/// `node`, or `None` if `node` is not inside one. Used to scope textual
/// scans to a single function and avoid cross-function pollution (e.g. a
/// bad-section `memset` bleeding into good-section analysis).
pub fn enclosing_function_lines(node: &tree_sitter::Node) -> Option<(usize, usize)> {
    let mut current = node.parent();
    while let Some(n) = current {
        if n.kind() == "function_definition" {
            return Some((n.start_position().row, n.end_position().row));
        }
        current = n.parent();
    }
    None
}

/// Content length of a string buffer initialized by a `memset`/`wmemset`
/// fill immediately followed by an explicit null terminator, scoped to the
/// function enclosing `call_node` and to the lines before the call.
///
/// This is the *actual* string length written into `var_name`, which is more
/// precise than the buffer's declared capacity — the distinction that lets a
/// copy rule keep the bad-section overflow (fill length > destination) while
/// suppressing the good-section copy (fill length fits the destination).
///
/// Matches patterns like:
///   memset(var, 'A', 49);   var[49] = '\0';     → 49
///   wmemset(var, L'A', 49);  var[49] = L'\0';    → 49
///   memset(var, 'A', 50-1);  var[50-1] = '\0';   → 49
///
/// When several matching fills precede the call (control-flow variants), the
/// largest is returned (worst case).
pub fn memset_content_length(
    var_name: &str,
    source: &str,
    call_node: &tree_sitter::Node,
) -> Option<usize> {
    let (fn_start, fn_end) = enclosing_function_lines(call_node)?;
    let call_line = call_node.start_position().row;
    let lines: Vec<&str> = source.lines().collect();

    let mut best_size: Option<usize> = None;

    for i in fn_start..std::cmp::min(call_line, fn_end + 1) {
        if i >= lines.len() {
            break;
        }
        let trimmed = lines[i].trim();

        // Find wmemset( or memset( call
        let call_start = if let Some(pos) = trimmed.find("wmemset(") {
            pos + "wmemset(".len()
        } else if let Some(pos) = trimmed.find("memset(") {
            pos + "memset(".len()
        } else {
            continue;
        };

        // Extract arguments between parens
        let after_call = &trimmed[call_start..];
        let close_paren = match after_call.rfind(')') {
            Some(p) => p,
            None => continue,
        };
        let args_str = &after_call[..close_paren];
        let parts: Vec<&str> = args_str.splitn(3, ',').collect();
        if parts.len() != 3 {
            continue;
        }

        // First arg must be exactly our variable name
        if parts[0].trim() != var_name {
            continue;
        }

        // Third arg is the fill count
        let size = match parse_simple_size_expr(parts[2].trim()) {
            Some(s) => s,
            None => continue,
        };

        // Verify null termination follows within next 3 lines
        let null_term_prefix = format!("{}[", var_name);
        let search_end = std::cmp::min(i + 4, lines.len());
        for next_line in lines[(i + 1)..search_end].iter().map(|l| l.trim()) {
            if next_line.contains(&null_term_prefix)
                && (next_line.contains("'\\0'") || next_line.contains("L'\\0'"))
            {
                // Keep the largest content size seen (conservative: if multiple
                // branches set different sizes, use the worst case)
                best_size = Some(match best_size {
                    Some(prev) => std::cmp::max(prev, size),
                    None => size,
                });
                break;
            }
        }
    }
    best_size
}

/// Evaluate a parenthesised allocation-size arithmetic capture of the form
/// `(N op M)` (or a bare `N`), as produced by the malloc/alloca size regexes.
/// `op` is `Some("+"|"-"|"*")` with both operands present, or `None` for a
/// bare `N` (in which case `b` must also be `None`). All other shapes — a
/// missing left operand, an unrecognised operator, or an operator without a
/// right operand — yield `None`. Overflow saturates to `None` via the
/// `checked_*` operations.
pub fn eval_arith(a: Option<usize>, op: Option<&str>, b: Option<usize>) -> Option<usize> {
    match (a, op, b) {
        (Some(a), Some("+"), Some(b)) => a.checked_add(b),
        (Some(a), Some("-"), Some(b)) => a.checked_sub(b),
        (Some(a), Some("*"), Some(b)) => a.checked_mul(b),
        (Some(a), None, None) => Some(a),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_arithmetic_two_operands_only() {
        assert_eq!(evaluate_simple_arithmetic("10 + 1"), Some(11));
        assert_eq!(evaluate_simple_arithmetic("50 - 1"), Some(49));
        // Three operands and multiplication are out of scope.
        assert_eq!(evaluate_simple_arithmetic("1 + 2 + 3"), None);
        assert_eq!(evaluate_simple_arithmetic("5 * 4"), None);
    }

    #[test]
    fn numeric_value_strips_parens_and_evaluates() {
        assert_eq!(extract_numeric_value("100"), Some(100));
        assert_eq!(extract_numeric_value("(10+1)"), Some(11));
        // Negative results are rejected (the size domain is unsigned).
        assert_eq!(extract_numeric_value("1-5"), None);
    }

    #[test]
    fn sizeof_uses_fixedwidth_table_with_pointer_default() {
        assert_eq!(extract_sizeof_value("sizeof(int)"), Some(4));
        assert_eq!(extract_sizeof_value("sizeof(char)"), Some(1));
        assert_eq!(extract_sizeof_value("sizeof(wchar_t)"), Some(4));
        // Unknown type falls back to pointer size.
        assert_eq!(extract_sizeof_value("sizeof(struct foo)"), Some(8));
        // No sizeof at all → None (distinct from the size-8 fallback).
        assert_eq!(extract_sizeof_value("42"), None);
    }

    #[test]
    fn malloc_size_returns_element_count_bytes_returns_total() {
        // N * sizeof(T): element count vs byte total diverge here.
        assert!(matches!(
            calculate_malloc_size("5 * sizeof(int)"),
            Some(BufferSize::DynamicCalculated(5))
        ));
        assert_eq!(calculate_alloc_bytes("5 * sizeof(int)"), Some(20));
        // Variable count → Dynamic, never misread as sizeof(char)=1.
        assert!(matches!(
            calculate_malloc_size("n * sizeof(char)"),
            Some(BufferSize::Dynamic(_))
        ));
    }

    #[test]
    fn eval_arith_matches_checked_semantics() {
        assert_eq!(eval_arith(Some(10), Some("+"), Some(1)), Some(11));
        assert_eq!(eval_arith(Some(10), Some("-"), Some(3)), Some(7));
        assert_eq!(eval_arith(Some(4), Some("*"), Some(3)), Some(12));
        // Bare N (no operator) passes through.
        assert_eq!(eval_arith(Some(8), None, None), Some(8));
        // Underflow/overflow and malformed shapes yield None.
        assert_eq!(eval_arith(Some(3), Some("-"), Some(5)), None);
        assert_eq!(eval_arith(Some(usize::MAX), Some("+"), Some(1)), None);
        assert_eq!(eval_arith(None, Some("+"), Some(1)), None);
        assert_eq!(eval_arith(Some(1), Some("/"), Some(1)), None);
    }
}
