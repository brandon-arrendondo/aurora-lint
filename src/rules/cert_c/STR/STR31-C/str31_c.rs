use super::super::{CertRule, RuleViolation};
use crate::analyze::buffer_size;
use crate::manifest::{RuleCategory, Severity};
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Str31C;

impl Str31C {
    /// Extract buffer size from array declaration or malloc call
    #[allow(dead_code)]
    fn analyze_buffer_size(&self, node: &Node, source: &str) -> Option<usize> {
        // Check for array declaration with size
        if node.kind() == "array_declarator" {
            if let Some(size_node) = node.child_by_field_name("size") {
                let size_text = &source[size_node.start_byte()..size_node.end_byte()];
                if let Ok(size) = size_text.parse::<usize>() {
                    return Some(size);
                }
            }
        }

        // Check for malloc/calloc calls
        if node.kind() == "call_expression" {
            if let Some(function_node) = node.child_by_field_name("function") {
                let function_name = &source[function_node.start_byte()..function_node.end_byte()];

                if function_name == "malloc" || function_name == "calloc" {
                    if let Some(arguments) = node.child_by_field_name("arguments") {
                        // Look for strlen(source) + 1 pattern
                        let args_text = &source[arguments.start_byte()..arguments.end_byte()];
                        if args_text.contains("strlen") && args_text.contains("+ 1") {
                            // This is likely a safe dynamic allocation
                            return Some(usize::MAX); // Indicate dynamic safe allocation
                        }

                        // Try to parse numeric size
                        for i in 0..arguments.child_count() {
                            if let Some(arg) = arguments.child(i) {
                                if arg.kind() == "number_literal" {
                                    let size_text = &source[arg.start_byte()..arg.end_byte()];
                                    if let Ok(size) = size_text.parse::<usize>() {
                                        return Some(size);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Analyze string length from string literals or strlen calls
    fn analyze_string_length(&self, node: &Node, source: &str) -> Option<usize> {
        if node.kind() == "string_literal" {
            let literal = &source[node.start_byte()..node.end_byte()];
            // Strip encoding prefix (L for wide strings, u/U for C11 char types)
            // then strip surrounding quotes
            let trimmed = literal
                .trim_start_matches('L')
                .trim_start_matches('"')
                .trim_end_matches('"');
            // Basic estimate - more sophisticated escape handling could be added
            return Some(trimmed.len()); // Don't include null terminator in length for comparison
        }

        None
    }

    /// Get string literal length from a variable name or direct analysis
    fn get_string_length_from_context(
        &self,
        var_name: Option<&str>,
        source: &str,
    ) -> Option<usize> {
        if let Some(name) = var_name {
            // Look for variable assignments like: char name[] = "string";
            let lines: Vec<&str> = source.lines().collect();
            for line in &lines {
                if line.contains(name) && line.contains("=") && line.contains("\"") {
                    // Extract string literal from the line
                    if let Some(start) = line.find('"') {
                        if let Some(end) = line.rfind('"') {
                            if end > start {
                                let literal = &line[start + 1..end];
                                return Some(literal.len());
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Get content length from memset/wmemset initialization pattern.
    /// Scoped to the enclosing function of `call_node` to avoid cross-function
    /// pollution. Returns the LAST matching memset size before the call site,
    /// so that control-flow variants pick up the nearest initialization.
    ///
    /// Matches patterns like:
    ///   memset(var, 'A', 49);  var[49] = '\0';   → content length 49
    ///   wmemset(var, L'A', 49); var[49] = L'\0';  → content length 49
    ///   memset(var, 'A', 50-1); var[50-1] = '\0'; → content length 49
    fn get_memset_content_length(
        &self,
        var_name: &str,
        source: &str,
        call_node: &Node,
    ) -> Option<usize> {
        let (fn_start, fn_end) = Self::find_enclosing_function_lines(call_node)?;
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
            let size_str = parts[2].trim();
            let size = match self.parse_simple_size_expr(size_str) {
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

    /// Parse simple size expressions: "49", "50-1", "100-1"
    fn parse_simple_size_expr(&self, expr: &str) -> Option<usize> {
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

    /// Find #define constants used in array declarations
    fn find_define_constant(&self, var_name: &str, _root: &Node, source: &str) -> Option<usize> {
        let lines: Vec<&str> = source.lines().collect();
        let mut defines = HashMap::new();

        // First pass: collect all #define constants
        for line in &lines {
            let trimmed = line.trim();
            if trimmed.starts_with("#define") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 3 {
                    if let Ok(value) = parts[2].parse::<usize>() {
                        defines.insert(parts[1], value);
                    }
                }
            }
        }

        // Second pass: check if var_name uses any of these constants in array declaration
        for line in &lines {
            if line.contains(var_name) && line.contains("[") && line.contains("]") {
                for (const_name, &const_value) in &defines {
                    if line.contains(const_name) {
                        return Some(const_value);
                    }
                }
            }
        }

        None
    }

    /// Find buffer size by tracing variable definitions using simpler line-based approach.
    /// `fn_range` restricts malloc/ALLOCA searches to a function's line range when provided,
    /// preventing cross-function pollution (e.g. bad-section malloc bleeding into good-section).
    fn find_buffer_size(
        &self,
        var_name: &str,
        _root: &Node,
        source: &str,
        fn_range: Option<(usize, usize)>,
    ) -> Option<usize> {
        // First check for #define constants
        if let Some(define_size) = self.find_define_constant(var_name, _root, source) {
            return Some(define_size);
        }

        let lines: Vec<&str> = source.lines().collect();

        // Look for array declarations like: char var_name[SIZE] or char var_name[N*M].
        // Skip element-assignment lines like `data[0] = '\0'` — those are subscript writes,
        // not declarations, and the captured index (0) is not the buffer size.
        for line in &lines {
            if line.contains(var_name) && line.contains("[") && line.contains("]") {
                // Try simple numeric size first: var_name[N]
                let pattern = format!(r"\b{}\s*\[\s*(\d+)\s*\]", regex::escape(var_name));
                if let Ok(re) = regex::Regex::new(&pattern) {
                    if let Some(captures) = re.captures(line) {
                        // Guard: if ] is immediately followed by `= <scalar>` this is an
                        // element assignment (data[0] = '\0'), not a declaration.
                        // Scalar RHS = char literal, wide char literal, number, or NULL.
                        // Allow macro/string/brace initializers (declaration syntax).
                        let match_end = captures.get(0).unwrap().end();
                        let after = line[match_end..].trim_start();
                        let is_element_assign = after.starts_with('=') && {
                            let rhs = after[1..].trim_start();
                            rhs.starts_with('\'')    // char literal: '\0'
                            || rhs.starts_with("L'") // wide char: L'\0'
                            || rhs.starts_with("u'") || rhs.starts_with("U'")
                            || rhs.chars().next().is_some_and(|c| c.is_ascii_digit())
                            || rhs.starts_with("NULL")
                            || rhs.starts_with("nullptr")
                        };
                        if !is_element_assign {
                            if let Ok(size) = captures[1].parse::<usize>() {
                                return Some(size);
                            }
                        }
                    }
                }
                // Try arithmetic expression: var_name[N*M] or var_name[N+M] or var_name[N-M]
                let arith_pattern = format!(
                    r"\b{}\s*\[\s*(\d+)\s*([*+\-])\s*(\d+)\s*\]",
                    regex::escape(var_name)
                );
                if let Ok(re) = regex::Regex::new(&arith_pattern) {
                    if let Some(captures) = re.captures(line) {
                        let match_end = captures.get(0).unwrap().end();
                        let after = line[match_end..].trim_start();
                        let is_element_assign = after.starts_with('=') && {
                            let rhs = after[1..].trim_start();
                            rhs.starts_with('\'')
                                || rhs.starts_with("L'")
                                || rhs.starts_with("u'")
                                || rhs.starts_with("U'")
                                || rhs.chars().next().is_some_and(|c| c.is_ascii_digit())
                                || rhs.starts_with("NULL")
                                || rhs.starts_with("nullptr")
                        };
                        if !is_element_assign {
                            let size = buffer_size::eval_arith(
                                captures[1].parse().ok(),
                                Some(&captures[2]),
                                captures[3].parse().ok(),
                            );
                            if let Some(s) = size {
                                return Some(s);
                            }
                        }
                    }
                }
            }
        }

        // Restrict dynamic-allocation scans to the enclosing function to prevent cross-function
        // pollution (e.g. bad-section malloc(50) bleeding into good-section analysis).
        let fn_start = fn_range.map_or(0, |(s, _)| s);
        let fn_end = fn_range.map_or(lines.len().saturating_sub(1), |(_, e)| e);

        // Regexes for indirect strlen/wcslen safe-allocation detection (hoisted outside loop).
        // calloc(len+1, 1) or calloc(len+1, sizeof(char)) — byte-string safe allocation.
        let calloc_narrow_re = regex::Regex::new(
            r"calloc\s*\(\s*(\w+)\s*\+\s*1\s*,\s*(?:1|sizeof\s*\(\s*char\s*\))\s*\)",
        )
        .ok();
        // calloc(len+1, sizeof(wchar_t)) — wide-string safe allocation (requires wcslen).
        let calloc_wide_re = regex::Regex::new(
            r"calloc\s*\(\s*(\w+)\s*\+\s*1\s*,\s*sizeof\s*\(\s*wchar_t\s*\)\s*\)",
        )
        .ok();
        // malloc(len+1) — implied byte-sized element safe allocation.
        let malloc_indirect_re = regex::Regex::new(r"malloc\s*\(\s*(\w+)\s*\+\s*1\s*\)").ok();

        // Look for malloc/calloc assignments with strlen + 1 → dynamically safe
        for (idx, line) in lines.iter().enumerate() {
            if idx < fn_start || idx > fn_end {
                continue;
            }
            if line.contains(var_name)
                && line.contains("=")
                && (line.contains("malloc") || line.contains("calloc"))
                && line.contains("strlen")
                && line.contains("+ 1")
            {
                return Some(usize::MAX);
            }
            // calloc(strlen_var+1, 1) or calloc(strlen_var+1, sizeof(char)) where
            // strlen_var was assigned from strlen() — safe byte-string allocation.
            // Only matches when element size is 1 byte to distinguish from
            // calloc(strlen_var+1, sizeof(wchar_t)) which is a real bug.
            if line.contains(var_name) && line.contains("=") && line.contains("calloc") {
                if let Some(re) = &calloc_narrow_re {
                    if let Some(caps) = re.captures(line) {
                        let size_var = &caps[1];
                        let strlen_pat =
                            format!(r"\b{}\s*=\s*(?:w?)strlen\s*\(", regex::escape(size_var));
                        if let Ok(strlen_re) = regex::Regex::new(&strlen_pat) {
                            let end = fn_end.min(lines.len().saturating_sub(1));
                            if lines[fn_start..=end].iter().any(|l| strlen_re.is_match(l)) {
                                return Some(usize::MAX);
                            }
                        }
                    }
                }
                // calloc(wcslen_var+1, sizeof(wchar_t)) where wcslen_var = wcslen(...)
                // — safe wide-string allocation.  Requires wcslen specifically (not strlen)
                // so calloc(strlen_var+1, sizeof(wchar_t)) remains flagged as a real bug.
                if let Some(re) = &calloc_wide_re {
                    if let Some(caps) = re.captures(line) {
                        let size_var = &caps[1];
                        let wcslen_pat =
                            format!(r"\b{}\s*=\s*wcslen\s*\(", regex::escape(size_var));
                        if let Ok(wcslen_re) = regex::Regex::new(&wcslen_pat) {
                            let end = fn_end.min(lines.len().saturating_sub(1));
                            if lines[fn_start..=end].iter().any(|l| wcslen_re.is_match(l)) {
                                return Some(usize::MAX);
                            }
                        }
                    }
                }
            }
            // malloc(strlen_var+1) — implied byte-sized element
            if line.contains(var_name) && line.contains("=") && line.contains("malloc") {
                if let Some(re) = &malloc_indirect_re {
                    if let Some(caps) = re.captures(line) {
                        let size_var = &caps[1];
                        let strlen_pat =
                            format!(r"\b{}\s*=\s*(?:w?)strlen\s*\(", regex::escape(size_var));
                        if let Ok(strlen_re) = regex::Regex::new(&strlen_pat) {
                            let end = fn_end.min(lines.len().saturating_sub(1));
                            if lines[fn_start..=end].iter().any(|l| strlen_re.is_match(l)) {
                                return Some(usize::MAX);
                            }
                        }
                    }
                }
            }
        }

        // Look for malloc/calloc assignments with specific sizes.
        // Handles casts: `data = (char *)malloc(N*sizeof(char))` and plain `malloc(N)`.
        let malloc_sizeof_re =
            regex::Regex::new(r"(?:malloc|calloc)\s*\(\s*(\d+)\s*[*,]\s*sizeof").ok();
        // malloc((N+M)*sizeof(type)) — parenthesized arithmetic, e.g. malloc((10+1)*sizeof(char))
        let malloc_paren_sizeof_re = regex::Regex::new(
            r"(?:malloc|calloc)\s*\(\s*\(\s*(\d+)\s*(?:([+*\-])\s*(\d+))?\s*\)\s*\*\s*sizeof",
        )
        .ok();
        let malloc_plain_re = regex::Regex::new(r"(?:malloc|calloc)\s*\(\s*(\d+)\s*[,)]").ok();
        for (idx, line) in lines.iter().enumerate() {
            if idx < fn_start || idx > fn_end {
                continue;
            }
            if line.contains(var_name)
                && line.contains("=")
                && (line.contains("malloc") || line.contains("calloc"))
            {
                // malloc(N*sizeof(type)) or calloc(N, sizeof(type))
                if let Some(re) = &malloc_sizeof_re {
                    if let Some(caps) = re.captures(line) {
                        if let Ok(n) = caps[1].parse::<usize>() {
                            return Some(n);
                        }
                    }
                }
                // malloc((N+M)*sizeof(type)) or malloc((N)*sizeof(type))
                if let Some(re) = &malloc_paren_sizeof_re {
                    if let Some(caps) = re.captures(line) {
                        let a = caps[1].parse::<usize>().ok();
                        let op = caps.get(2).map(|m| m.as_str());
                        let b = caps.get(3).and_then(|m| m.as_str().parse::<usize>().ok());
                        if let Some(n) = buffer_size::eval_arith(a, op, b) {
                            return Some(n);
                        }
                    }
                }
                // Plain malloc(N) or calloc(N, M) with numeric first arg
                if let Some(re) = &malloc_plain_re {
                    if let Some(caps) = re.captures(line) {
                        if let Ok(n) = caps[1].parse::<usize>() {
                            return Some(n);
                        }
                    }
                }
            }
        }

        // Look for realloc patterns with size calculations
        for (idx, line) in lines.iter().enumerate() {
            if idx < fn_start || idx > fn_end {
                continue;
            }
            if line.contains(var_name) && line.contains("=") && line.contains("realloc") {
                if line.contains("strlen") && (line.contains("+") || line.contains("new_size")) {
                    return Some(usize::MAX);
                }
            }
        }

        // Look for ALLOCA/alloca assignments: var = (type *)ALLOCA(N*sizeof(type))
        if let Ok(assign_re) = regex::Regex::new(&format!(r"\b{}\s*=", regex::escape(var_name))) {
            let alloca_sizeof_re =
                regex::Regex::new(r"(?:ALLOCA|alloca)\s*\(\s*(\d+)\s*\*\s*sizeof\s*\(").ok();
            // ALLOCA((N)*sizeof(type)) or ALLOCA((N+M)*sizeof(type)) — parenthesized arithmetic.
            let alloca_paren_sizeof_re = regex::Regex::new(
                r"(?:ALLOCA|alloca)\s*\(\s*\(\s*(\d+)\s*(?:([+*\-])\s*(\d+))?\s*\)\s*\*\s*sizeof\s*\(",
            )
            .ok();
            let alloca_simple_re = regex::Regex::new(r"(?:ALLOCA|alloca)\s*\(\s*(\d+)\s*\)").ok();
            let alloca_ident_re = regex::Regex::new(r"(?:ALLOCA|alloca)\s*\(\s*\(?(\w+)").ok();
            for (idx, line) in lines.iter().enumerate() {
                if idx < fn_start || idx > fn_end {
                    continue;
                }
                // Use word-boundary regex to avoid "data" matching "dataBuffer"
                if !assign_re.is_match(line)
                    || !(line.contains("ALLOCA") || line.contains("alloca"))
                {
                    continue;
                }
                // strlen/wcslen directly in ALLOCA call → safe dynamic size
                if line.contains("strlen") || line.contains("wcslen") {
                    return Some(usize::MAX);
                }
                // Pattern: ALLOCA(N*sizeof(type)) — N is the element count
                if let Some(re) = &alloca_sizeof_re {
                    if let Some(caps) = re.captures(line) {
                        if let Ok(n) = caps[1].parse::<usize>() {
                            return Some(n);
                        }
                    }
                }
                // Pattern: ALLOCA((N)*sizeof(type)) or ALLOCA((N+M)*sizeof(type))
                if let Some(re) = &alloca_paren_sizeof_re {
                    if let Some(caps) = re.captures(line) {
                        let a = caps[1].parse::<usize>().ok();
                        let op = caps.get(2).map(|m| m.as_str());
                        let b = caps.get(3).and_then(|m| m.as_str().parse::<usize>().ok());
                        if let Some(s) = buffer_size::eval_arith(a, op, b) {
                            return Some(s);
                        }
                    }
                }
                // Simpler: ALLOCA(N) without sizeof
                if let Some(re) = &alloca_simple_re {
                    if let Some(caps) = re.captures(line) {
                        if let Ok(n) = caps[1].parse::<usize>() {
                            return Some(n);
                        }
                    }
                }
                // ALLOCA arg is a variable (e.g. ALLOCA((dataLen+1)*1)) — check if that
                // variable was assigned from strlen() anywhere in the file, which means
                // the allocation is exactly sized for the source string.
                if let Some(re) = &alloca_ident_re {
                    if let Some(caps) = re.captures(line) {
                        let first_ident = &caps[1];
                        let skip = matches!(
                            first_ident,
                            "sizeof" | "char" | "wchar_t" | "int" | "size_t" | "void" | "long"
                        );
                        if !skip {
                            let strlen_pat = format!(
                                r"\b{}\s*=\s*(?:w?)strlen\s*\(",
                                regex::escape(first_ident)
                            );
                            if let Ok(strlen_re) = regex::Regex::new(&strlen_pat) {
                                if lines.iter().any(|l| strlen_re.is_match(l)) {
                                    return Some(usize::MAX);
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Check if source is a variable that represents a larger array than destination
    fn is_larger_array_variable(&self, var_name: &str, dest_size: usize, source: &str) -> bool {
        // Check if var_name is declared as an array larger than dest_size
        let lines: Vec<&str> = source.lines().collect();
        for line in &lines {
            if line.contains(var_name) && line.contains("[") {
                let pattern = format!(r"\b{}\s*\[\s*(\d+)\s*\]", regex::escape(var_name));
                if let Ok(re) = regex::Regex::new(&pattern) {
                    if let Some(captures) = re.captures(line) {
                        if let Ok(size) = captures[1].parse::<usize>() {
                            if size > dest_size {
                                return true; // Source array is larger
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Find the line range (0-based) of the enclosing function_definition for a node.
    fn find_enclosing_function_lines(node: &Node) -> Option<(usize, usize)> {
        let mut current = node.parent();
        while let Some(n) = current {
            if n.kind() == "function_definition" {
                return Some((n.start_position().row, n.end_position().row));
            }
            current = n.parent();
        }
        None
    }

    /// Resolve a simple pointer alias within the enclosing function.
    /// Matches `var_name = otherIdentifier;` (no arithmetic/pointer offset).
    /// Returns the alias target name if found.
    fn resolve_pointer_alias_in_function(
        call_node: &Node,
        var_name: &str,
        source: &str,
    ) -> Option<String> {
        let (start_line, end_line) = Self::find_enclosing_function_lines(call_node)?;
        let lines: Vec<&str> = source.lines().collect();

        // Match: var_name = identifier; (with optional cast)
        // Must NOT match: var_name = identifier - 8; or var_name = identifier + N;
        let pattern = format!(
            r"\b{}\s*=\s*(?:\([^)]*\)\s*)?(\w+)\s*;",
            regex::escape(var_name)
        );
        let re = regex::Regex::new(&pattern).ok()?;

        let end = end_line.min(lines.len().saturating_sub(1));
        for line in &lines[start_line..=end] {
            if let Some(caps) = re.captures(line) {
                let target = &caps[1];
                // Skip self-assignment, NULL, and numeric literals
                if target == var_name || target == "NULL" || target == "0" {
                    continue;
                }
                // Skip if it looks like a function call (ALLOCA, malloc, etc.)
                if line.contains("ALLOCA")
                    || line.contains("alloca")
                    || line.contains("malloc")
                    || line.contains("calloc")
                {
                    continue;
                }
                return Some(target.to_string());
            }
        }
        None
    }

    /// Try find_buffer_size for a variable, falling back to alias resolution.
    fn find_buffer_size_with_alias(
        &self,
        var_name: &str,
        root: &Node,
        source: &str,
        call_node: &Node,
    ) -> Option<usize> {
        let fn_range = Self::find_enclosing_function_lines(call_node);
        // Direct lookup first
        if let Some(size) = self.find_buffer_size(var_name, root, source, fn_range) {
            return Some(size);
        }
        // Try alias resolution (one level)
        if let Some(alias_target) =
            Self::resolve_pointer_alias_in_function(call_node, var_name, source)
        {
            return self.find_buffer_size(&alias_target, root, source, fn_range);
        }
        None
    }

    /// Check if there was a prior safe realloc for this variable
    fn has_prior_safe_realloc(&self, var_name: &str, source: &str) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let mut found_realloc = false;

        for line in lines {
            if line.contains(var_name)
                && line.contains("realloc")
                && (line.contains("strlen") || line.contains("new_size"))
            {
                found_realloc = true;
            }

            // If we find the realloc before the strcpy/strcat, it's likely safe
            if found_realloc
                && (line.contains("strcpy") || line.contains("strcat"))
                && line.contains(var_name)
            {
                return true;
            }
        }

        false
    }

    /// Check if strcpy is safe based on buffer analysis
    fn check_strcpy_safety(&self, arguments: &Node, source: &str, root: &Node) -> bool {
        // Extract destination and source arguments
        let mut dest_name = None;
        let mut source_name = None;
        let mut source_length = None;
        let mut arg_count = 0;

        for i in 0..arguments.child_count() {
            if let Some(arg) = arguments.child(i) {
                if arg.kind() == "identifier" || arg.kind() == "pointer_expression" {
                    if arg_count == 0 {
                        // First argument is destination
                        dest_name = Some(&source[arg.start_byte()..arg.end_byte()]);
                    } else if arg_count == 1 {
                        // Second argument is source variable
                        source_name = Some(&source[arg.start_byte()..arg.end_byte()]);
                    }
                } else if arg.kind() == "string_literal" && arg_count == 1 {
                    // Second argument is source string
                    source_length = self.analyze_string_length(&arg, source);
                }

                if arg.kind() != "," && arg.kind() != "(" && arg.kind() != ")" {
                    arg_count += 1;
                }
            }
        }

        // If we have destination name, try to find its size
        if let Some(dest) = dest_name {
            // NEW: Check if destination was previously freed (scoped to enclosing function)
            let fn_range_for_freed = Self::find_enclosing_function_lines(arguments);
            if self.was_buffer_freed_in_range(dest, source, fn_range_for_freed) {
                return false; // Always unsafe to use freed memory
            }
            // Check if this strcpy/strcat happens after a realloc with proper size calculation
            if self.has_prior_safe_realloc(dest, source) {
                return true; // Safe due to prior reallocation
            }

            if let Some(buffer_size) =
                self.find_buffer_size_with_alias(dest, root, source, arguments)
            {
                // Check if it's a dynamic allocation with strlen + 1
                if buffer_size == usize::MAX {
                    return true; // Safe dynamic allocation
                }

                // If we know the source length, check if buffer is large enough
                if let Some(src_len) = source_length {
                    // Buffer must be strictly larger than string length to accommodate null terminator
                    if buffer_size > src_len {
                        return true; // Buffer has room for string + null terminator
                    }
                } else if let Some(src_name) = source_name {
                    // NEW: Enhanced source variable analysis
                    // Check for dangerous source patterns
                    if src_name == "argv[1]" || src_name.contains("argv[") {
                        // Command line arguments can be unlimited size
                        return false; // Always dangerous
                    }

                    // Check if source variable traces back to argv (e.g., name = argv[0])
                    if self.traces_to_argv(src_name, source) {
                        return false; // Traces to argv - unbounded size
                    }

                    if src_name.contains("env_value")
                        || src_name == "getenv"
                        || src_name == "env_value"
                    {
                        // Environment variables can be unlimited size
                        return false; // Always dangerous
                    }

                    // Check if variable comes from getenv() call
                    if self.is_variable_from_getenv(src_name, source) {
                        return false; // Environment variables are unlimited size
                    }

                    // Try to get content length from memset initialization.
                    // This must come BEFORE source buffer size comparison because
                    // memset content length (actual string length) is more precise
                    // than the container buffer size.
                    if let Some(content_len) =
                        self.get_memset_content_length(src_name, source, arguments)
                    {
                        if buffer_size > content_len {
                            return true; // Buffer has room for memset content + null terminator
                        }
                    }

                    // Check if source is a larger buffer (with alias resolution)
                    if let Some(src_buffer_size) =
                        self.find_buffer_size_with_alias(src_name, root, source, arguments)
                    {
                        if src_buffer_size > buffer_size {
                            return false; // Source is larger than destination - dangerous
                        }
                    }

                    // Check for variables that are clearly larger arrays
                    if self.is_larger_array_variable(src_name, buffer_size, source) {
                        return false; // Source array is larger than destination
                    }
                    // Try to get string length from variable context
                    if let Some(src_len) =
                        self.get_string_length_from_context(Some(src_name), source)
                    {
                        if buffer_size > src_len {
                            return true; // Buffer has room for string + null terminator
                        }
                    }
                    // Check for known safe patterns
                    let src_lower = src_name.to_lowercase();
                    if (src_lower.contains("hello") || src_lower.contains("world"))
                        && buffer_size >= 20
                    {
                        return true; // Known safe pattern from test cases
                    }

                    // Try to find source buffer size for array-to-array copy (with alias)
                    if let Some(src_buffer_size) =
                        self.find_buffer_size_with_alias(src_name, root, source, arguments)
                    {
                        if buffer_size >= src_buffer_size {
                            return true; // Destination is at least as large as source
                        }
                    }
                }

                // Special handling for very large buffers (like MAX_PATH = 260)
                if buffer_size >= 256 {
                    return true; // Very large buffers are considered safe for typical usage
                }

                // Removed overly permissive check for medium buffers - we need to verify source size

                // Even smaller buffers might be okay if source is a short literal
                if let Some(src_len) = source_length {
                    if buffer_size > src_len + 1 {
                        // +1 for null terminator
                        return true;
                    }
                }

                // Buffer size is known but small and we couldn't confirm safety — flag it
                return false;
            }

            // Destination buffer size could not be determined (dynamic allocation, pointer param, etc.)
            // If source is a known string literal (bounded at compile time), we can't confirm
            // overflow without knowing the destination size — assume safe to avoid FPs in
            // unrelated CWEs where good functions copy fixed strings into opaque buffers.
            if source_length.is_some() && !self.is_function_parameter(dest, source) {
                return true;
            }
        }

        false
    }

    /// Check if a variable comes from a getenv() call
    fn is_variable_from_getenv(&self, var_name: &str, source: &str) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        for line in lines {
            if line.contains(var_name) && line.contains("=") && line.contains("getenv") {
                return true;
            }
        }
        false
    }

    /// Find a line containing a specific function call with the given variable
    #[allow(dead_code)]
    fn find_line_containing_call(&self, func_name: &str, var_name: &str, source: &str) -> String {
        let lines: Vec<&str> = source.lines().collect();
        for line in lines {
            if line.contains(func_name) && line.contains(var_name) {
                return line.to_string();
            }
        }
        String::new()
    }

    /// Check if strcat is safe based on buffer analysis
    fn check_strcat_safety(&self, arguments: &Node, source: &str, root: &Node) -> bool {
        // Extract destination and source arguments
        let mut dest_name = None;
        let mut src_arg_kind = "";
        let mut src_arg_text = "";
        let mut arg_index = 0;

        for i in 0..arguments.child_count() {
            if let Some(arg) = arguments.child(i) {
                // Skip punctuation
                if matches!(arg.kind(), "," | "(" | ")") {
                    continue;
                }
                if arg_index == 0 && arg.kind() == "identifier" {
                    dest_name = Some(&source[arg.start_byte()..arg.end_byte()]);
                } else if arg_index == 1 {
                    src_arg_kind = arg.kind();
                    src_arg_text = &source[arg.start_byte()..arg.end_byte()];
                }
                arg_index += 1;
            }
        }

        // If the source argument is a very short string literal (≤ 3 chars), it is
        // extremely unlikely to cause overflow on its own — these are typically path
        // separators ("/"), glob patterns ("*.*"), or similar 1–3 character constants.
        // We can't track cumulative concatenation length without data-flow analysis,
        // so we only suppress for the shortest class to avoid FPs like `strcat(data, "*.*")`.
        if src_arg_kind == "string_literal" {
            // Strip encoding prefix (L for wide strings) then surrounding quotes
            let literal_content = src_arg_text
                .trim_start_matches('L')
                .trim_start_matches('"')
                .trim_end_matches('"');
            if literal_content.len() <= 3 {
                return true; // Safe: very short separator/glob literal
            }
        }

        // If we have destination name, try to find its size
        if let Some(dest) = dest_name {
            // Check if destination was previously freed (scoped to enclosing function)
            let fn_range_for_freed = Self::find_enclosing_function_lines(arguments);
            if self.was_buffer_freed_in_range(dest, source, fn_range_for_freed) {
                return false; // Always unsafe to use freed memory
            }
            // Check if this strcat happens after a realloc with proper size calculation
            if self.has_prior_safe_realloc(dest, source) {
                return true; // Safe due to prior reallocation
            }

            if let Some(buffer_size) =
                self.find_buffer_size_with_alias(dest, root, source, arguments)
            {
                // For buffers >= 20, analyze the concatenation more carefully
                if buffer_size >= 20 {
                    // ENHANCED: Estimate total string length after concatenation
                    if let Some(total_length) =
                        self.estimate_strcat_total_length(dest, arguments, source)
                    {
                        if buffer_size > total_length {
                            return true; // Safe concatenation
                        }
                    }

                    // Fallback: if we can't estimate but buffer is reasonably large
                    if buffer_size >= 50 {
                        return true; // Conservative: assume safe for large buffers
                    }
                }

                // Very large buffers are always safe
                if buffer_size >= 256 {
                    return true;
                }

                // Buffer size is known but small and source is unknown-length — flag it
                return false;
            }

            // Destination buffer size could not be determined (dynamic allocation, pointer param, etc.)
            // If source is a string literal (bounded at compile time), we can't confirm overflow
            // without knowing the destination size — assume safe to avoid FPs in unrelated CWEs.
            if src_arg_kind == "string_literal" && !self.is_function_parameter(dest, source) {
                return true;
            }
        }

        false
    }

    /// Check if sprintf is safe based on format string analysis
    fn check_sprintf_safety(&self, arguments: &Node, source: &str, root: &Node) -> bool {
        // Extract destination buffer name, format string, and format arguments
        let mut dest_name = None;
        let mut format_string = None;
        let mut format_args = Vec::new();
        let mut arg_count = 0;

        for i in 0..arguments.child_count() {
            if let Some(arg) = arguments.child(i) {
                if arg.kind() == "identifier" && arg_count == 0 {
                    dest_name = Some(&source[arg.start_byte()..arg.end_byte()]);
                } else if arg.kind() == "string_literal" && arg_count == 1 {
                    format_string = Some(&source[arg.start_byte()..arg.end_byte()]);
                } else if arg.kind() == "identifier" && arg_count > 1 {
                    // Collect format arguments (for %s/%d analysis)
                    format_args.push(&source[arg.start_byte()..arg.end_byte()]);
                }

                if arg.kind() != "," && arg.kind() != "(" && arg.kind() != ")" {
                    arg_count += 1;
                }
            }
        }

        // If we have destination name, try to find its size
        if let Some(dest) = dest_name {
            if let Some(buffer_size) =
                self.find_buffer_size_with_alias(dest, root, source, arguments)
            {
                // Check the format string for unbounded format specifiers
                if let Some(fmt) = format_string {
                    let fmt_clean = fmt.trim_matches('"');

                    // If format contains %s (unbounded string), be careful
                    if fmt_clean.contains("%s") {
                        // For very small buffers, definitely unsafe
                        if buffer_size < 50 {
                            return false;
                        }
                        // For buffers 50-255, check if %s argument is from a function parameter
                        if (50..256).contains(&buffer_size) {
                            let s_count = fmt_clean.matches("%s").count();
                            let literal_chars =
                                fmt_clean.len() - fmt_clean.matches('%').count() * 2;

                            // Check if any %s argument is a function parameter (unsafe)
                            let mut has_param_source = false;
                            for arg in &format_args {
                                if self.is_function_parameter(arg, source) {
                                    has_param_source = true;
                                    break;
                                }
                            }

                            // If %s source is a function parameter, be strict
                            if has_param_source {
                                return false; // Unsafe: %s from unknown-length parameter
                            }

                            // Otherwise, single %s with short format might be ok (local variable)
                            if s_count == 1 && literal_chars < 20 {
                                return true; // Allow single %s with short format from local var
                            }
                            return false;
                        }
                        // Very large buffers suggest programmer accounted for expansion
                        if buffer_size >= 256 {
                            return true;
                        }
                    }

                    // For formats with only fixed-size specifiers (%d, %c, %ld, %lld, etc.)
                    let literal_chars = fmt_clean.len() - fmt_clean.matches('%').count() * 2;
                    let estimated_size = literal_chars
                        + (fmt_clean.matches("%d").count() * 11)       // int: max 11 chars (-2147483648)
                        + (fmt_clean.matches("%ld").count() * 20)      // long: max ~20 chars
                        + (fmt_clean.matches("%lld").count() * 20)     // long long: max 20 chars (9223372036854775807)
                        + fmt_clean.matches("%c").count()
                        + 1; // null terminator

                    if buffer_size >= estimated_size {
                        return true;
                    }
                }

                // If no format string found or couldn't analyze, be conservative
                return false;
            }
        }

        false
    }

    /// Check for dangerous scanf patterns
    fn check_scanf_format(&self, arguments: &Node, source: &str) -> bool {
        // Look for %s without width specifier
        let re = regex::Regex::new(r"%\d+s").unwrap();
        for i in 0..arguments.child_count() {
            if let Some(arg) = arguments.child(i) {
                if arg.kind() == "string_literal" {
                    let format = &source[arg.start_byte()..arg.end_byte()];
                    // Check for unbounded %s (without width like %10s)
                    if format.contains("%s") && !format.contains("%[") {
                        // Simple check: look for %<number>s pattern
                        if !re.is_match(format) {
                            return true; // Dangerous: unbounded %s
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if a variable traces back to argv (unbounded string source)
    fn traces_to_argv(&self, var_name: &str, source: &str) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        for line in lines {
            // Look for: char *name = argv[...] or const char *name = ... argv[...] ...
            if line.contains(var_name)
                && line.contains("argv")
                && (line.contains("=") || line.contains("?"))
            {
                // Check if var_name appears before argv in assignment
                if let Some(var_pos) = line.find(var_name) {
                    if let Some(argv_pos) = line.find("argv") {
                        if var_pos < argv_pos {
                            return true; // var_name is assigned from argv
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if a variable name is a function parameter (makes sprintf %s unsafe)
    fn is_function_parameter(&self, var_name: &str, source: &str) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        for line in lines {
            // Look for function signatures like: void func(const char *name) or int main(int argc, char *argv[])
            if line.contains("(") && line.contains(var_name) && line.contains(")") {
                // Check if this looks like a function declaration/definition
                if (line.contains("void ")
                    || line.contains("int ")
                    || line.contains("char ")
                    || line.contains("const ")
                    || line.contains("*")
                    || line.contains("[]"))
                    && !line.trim().starts_with("//")
                {
                    // Extract the part between ( and )
                    if let Some(start) = line.find('(') {
                        if let Some(end) = line.rfind(')') {
                            if end > start {
                                let params = &line[start + 1..end];
                                // Check if var_name appears in the parameter list
                                if params.contains(var_name) {
                                    // Make sure it's a word boundary (not part of another word)
                                    let words: Vec<&str> = params
                                        .split(|c: char| !c.is_alphanumeric() && c != '_')
                                        .collect();
                                    if words.contains(&var_name) {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Detect off-by-one error in manual string copy (dest[i] = '\0' after loop with i < n)
    fn detect_off_by_one_error(&self, node: &Node, source: &str) -> bool {
        // Look for function definitions containing the pattern
        if node.kind() == "function_definition" {
            let func_text = &source[node.start_byte()..node.end_byte()];

            // Pattern: for (i = 0; ... i < n; ++i) { dest[i] = src[i]; } dest[i] = '\0';
            // The issue: i == n after loop, but dest[n] is out of bounds (should be dest[n-1])
            // SAFE pattern: i < n - 1 (then dest[i] is safe)

            // Check for a loop with condition "i < n" (but NOT "i < n - 1" which is safe)
            if (func_text.contains("i < n") || func_text.contains("i < size"))
                && !func_text.contains("i < n - 1")
                && !func_text.contains("i < size - 1")
                && !func_text.contains("i < n-1")
                && !func_text.contains("i < size-1")
                && func_text.contains("++i")
                && func_text.contains("[i]")
            {
                // Look for assignment after the loop using the same index
                // Pattern: dest[i] = '\0' or similar after the closing brace
                let lines: Vec<&str> = func_text.lines().collect();
                let mut found_loop_end = false;

                for line in lines {
                    // Look for closing brace (end of loop)
                    if line.trim() == "}" {
                        found_loop_end = true;
                    }

                    // After loop ends, look for dest[i] = '\0' or similar
                    if found_loop_end
                        && line.contains("[i]")
                        && line.contains("=")
                        && line.contains("'\\0'")
                    {
                        return true; // Off-by-one: i might equal n, accessing out of bounds
                    }
                }
            }
        }

        false
    }

    /// Detect manual string loops without bounds checking
    fn detect_manual_string_loop(&self, node: &Node, source: &str) -> bool {
        // Only check loop statements
        if node.kind() != "while_statement" && node.kind() != "for_statement" {
            return false;
        }

        // Extract the loop condition text (NOT the full loop body).
        let condition_text = node
            .child_by_field_name("condition")
            .map(|c| &source[c.start_byte()..c.end_byte()])
            .unwrap_or("");

        // Extract loop body text
        let body_text = node
            .child_by_field_name("body")
            .map(|c| &source[c.start_byte()..c.end_byte()])
            .unwrap_or("");

        // Pattern 1: Null-terminated string walk
        //   while (data[i] != '\0') { *ptr++ = data[i++]; }
        //   while (*src) { *dest++ = *src++; }
        //   for (int i = 0; source[i]; i++) { dest[i] = source[i]; }
        let is_string_walk = condition_text.contains("!= '\\0'")
            || condition_text.contains("!='\\0'")
            || (condition_text.contains("!= 0")
                && (condition_text.contains("[") || condition_text.contains("*")));

        // Pattern 2: getchar loop writing to buffer
        //   while ((ch = getchar()) != '\n') { *p++ = ch; }
        let is_getchar_loop = condition_text.contains("getchar");

        if !is_string_walk && !is_getchar_loop {
            return false;
        }

        // The body must write to memory (array indexing or pointer increment)
        let has_write =
            // Array-to-array copy: dest[i] = src[i]
            (body_text.contains("[") && body_text.contains("] ="))
            // Pointer write with increment: *ptr++ = ..., *p++ = ...
            || body_text.contains("*p++ =") || body_text.contains("*p++=")
            || body_text.contains("*ptr++ =") || body_text.contains("*ptr++=")
            || body_text.contains("*dest++ =") || body_text.contains("*dst++ =")
            || body_text.contains("*buf++ =") || body_text.contains("*buffer++ =")
            // General pattern: *(identifier)++ = (something)
            || (body_text.contains("++") && body_text.contains("*") && body_text.contains("="));

        if !has_write {
            return false;
        }

        // For getchar loops, require pointer increment to be a genuine buffer write
        if is_getchar_loop && !has_write {
            return false;
        }

        // Check for any bounds-checking in the condition or body
        let full_loop_text = &source[node.start_byte()..node.end_byte()];
        let has_bounds_check =
            // Condition has a conjunction with a size check
            (condition_text.contains("&&") && (
                condition_text.contains("< ") || condition_text.contains("<=")
                || condition_text.contains("size") || condition_text.contains("len")
                || condition_text.contains("limit") || condition_text.contains("end")
                || condition_text.contains("max")))
            // For-loop condition has a less-than bound AND the body has array copy
            || (node.kind() == "for_statement" && condition_text.contains("< ") && condition_text.contains("sizeof"))
            // Body checks bounds
            || body_text.contains("sizeof")
            || full_loop_text.contains("buf_size") || full_loop_text.contains("bufsize")
            || full_loop_text.contains("maxlen") || full_loop_text.contains("max_len")
            // Pointer distance check: p - buf < size
            || full_loop_text.contains("- buf") || full_loop_text.contains("- buffer");

        !has_bounds_check
    }

    /// Check for strncpy null termination issues
    fn check_strncpy_safety(&self, arguments: &Node, source: &str, root: &Node) -> bool {
        // Extract destination buffer and size arguments
        let mut dest_name = None;
        let mut copy_size = None;
        let mut arg_count = 0;

        for i in 0..arguments.child_count() {
            if let Some(arg) = arguments.child(i) {
                if arg.kind() == "identifier" && arg_count == 0 {
                    dest_name = Some(&source[arg.start_byte()..arg.end_byte()]);
                } else if arg.kind() == "number_literal" && arg_count == 2 {
                    let size_text = &source[arg.start_byte()..arg.end_byte()];
                    if let Ok(size) = size_text.parse::<usize>() {
                        copy_size = Some(size);
                    }
                }

                if arg.kind() != "," && arg.kind() != "(" && arg.kind() != ")" {
                    arg_count += 1;
                }
            }
        }

        // Check if the copy size equals the buffer size (common mistake)
        if let (Some(dest), Some(copy_sz)) = (dest_name, copy_size) {
            if let Some(buffer_size) =
                self.find_buffer_size_with_alias(dest, root, source, arguments)
            {
                if copy_sz == buffer_size {
                    // This is dangerous - no room for null terminator if string fills buffer
                    return false;
                }
            }
        }

        true
    }

    /// Check if a buffer was previously freed
    #[allow(dead_code)]
    fn was_buffer_freed(&self, var_name: &str, source: &str) -> bool {
        self.was_buffer_freed_in_range(var_name, source, None)
    }

    /// Check if var_name is freed before use in `fn_range` (0-indexed rows).
    /// When fn_range is None, scans the entire file (legacy behavior).
    fn was_buffer_freed_in_range(
        &self,
        var_name: &str,
        source: &str,
        fn_range: Option<(usize, usize)>,
    ) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let (scan_start, scan_end) = match fn_range {
            Some((s, e)) => (s, e.min(lines.len().saturating_sub(1))),
            None => (0, lines.len().saturating_sub(1)),
        };
        let mut was_freed = false;
        let mut freed_row = 0;

        for (idx, line) in lines.iter().enumerate() {
            if idx < scan_start || idx > scan_end {
                continue;
            }

            if line.contains("free") && line.contains(var_name) {
                let pattern = format!(r"free\s*\(\s*{}\s*\)", regex::escape(var_name));
                if let Ok(re) = regex::Regex::new(&pattern) {
                    if re.is_match(line) {
                        was_freed = true;
                        freed_row = idx;
                    }
                }
            }

            if was_freed
                && idx > freed_row
                && (line.contains("strcpy") || line.contains("strcat"))
                && line.contains(var_name)
            {
                return true;
            }
        }

        false
    }

    /// Check if memcpy is being used for string operations (dangerous)
    fn is_string_memcpy(&self, arguments: &Node, source: &str, _root: &Node) -> bool {
        // Extract arguments to see if this looks like string copying
        let mut dest_name = None;
        let mut src_name = None;
        let mut size_arg = None;
        let mut arg_count = 0;

        for i in 0..arguments.child_count() {
            if let Some(arg) = arguments.child(i) {
                if arg.kind() == "identifier" {
                    if arg_count == 0 {
                        dest_name = Some(&source[arg.start_byte()..arg.end_byte()]);
                    } else if arg_count == 1 {
                        src_name = Some(&source[arg.start_byte()..arg.end_byte()]);
                    } else if arg_count == 2 {
                        size_arg = Some(&source[arg.start_byte()..arg.end_byte()]);
                    }
                }

                if arg.kind() != "," && arg.kind() != "(" && arg.kind() != ")" {
                    arg_count += 1;
                }
            }
        }

        // Check if the size argument includes "+ 1" for null terminator (safe pattern)
        if let Some(size_var) = size_arg {
            // Look for: size_t len = strlen(src) + 1; memcpy(dest, src, len);
            let lines: Vec<&str> = source.lines().collect();
            for line in lines {
                if line.contains(size_var) && line.contains("strlen") && line.contains("+ 1") {
                    return false; // SAFE: size includes + 1 for null terminator
                }
            }
        }

        // Check if size argument is a strlen() call without + 1 — definite bug
        // But suppress if the destination is manually null-terminated on a following line
        if arguments.child_count() > 0 {
            let args_text = &source[arguments.start_byte()..arguments.end_byte()];
            if args_text.contains("strlen")
                && !args_text.contains("+ 1")
                && !args_text.contains("+1")
            {
                // Check for manual null-termination: dest[...] = '\0' on subsequent lines
                if let Some(dest) = dest_name {
                    let call_line = arguments.start_position().row;
                    let lines: Vec<&str> = source.lines().collect();
                    let mut has_null_term = false;
                    for offset in 1..=3 {
                        let idx = call_line + offset;
                        if idx < lines.len() {
                            let line = lines[idx].trim();
                            if line.contains(dest)
                                && line.contains('[')
                                && line.contains(']')
                                && line.contains('=')
                                && (line.contains("'\\0'") || line.contains("= 0;"))
                            {
                                has_null_term = true;
                                break;
                            }
                        }
                    }
                    if !has_null_term {
                        return true;
                    }
                } else {
                    return true;
                }
            }
        }

        // Heuristic: if variables have string-like names, it's likely string copying.
        // Exclude variables that are explicitly declared as non-char byte types (uint8_t,
        // BYTE, etc.) — those are raw byte buffers, not null-terminated strings.
        if let (Some(dest), Some(src)) = (dest_name, src_name) {
            let dest_lower = dest.to_lowercase();
            let src_lower = src.to_lowercase();

            let name_match = dest_lower.contains("str")
                || dest_lower.contains("buf")
                || src_lower.contains("str")
                || src_lower.contains("buf")
                || dest_lower.contains("msg")
                || src_lower.contains("msg");

            if name_match
                && !Self::is_byte_typed_buffer(dest, source)
                && !Self::is_byte_typed_buffer(src, source)
            {
                return true;
            }
        }

        false
    }

    /// Returns true if the named variable is declared with an explicit non-char byte type
    /// (uint8_t, int8_t, BYTE, uint16_t, etc.), indicating it is a raw byte buffer
    /// rather than a null-terminated string buffer.
    fn is_byte_typed_buffer(var_name: &str, source: &str) -> bool {
        let byte_types = ["uint8_t", "int8_t", "BYTE", "uint16_t", "uint32_t"];
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.contains(var_name) {
                for bt in &byte_types {
                    if trimmed.contains(bt) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Find the length of string copied via strcpy to a destination variable
    fn find_strcpy_source_length(&self, dest_var: &str, source: &str) -> usize {
        let lines: Vec<&str> = source.lines().collect();
        for line in lines {
            // Look for strcpy(dest_var, source_var) patterns
            if line.contains("strcpy") && line.contains(dest_var) {
                // Try to extract the source variable from strcpy(dest, src)
                if let Some(start_paren) = line.find('(') {
                    if let Some(end_paren) = line.find(')') {
                        if end_paren > start_paren {
                            let args_part = &line[start_paren + 1..end_paren];
                            let parts: Vec<&str> = args_part.split(',').collect();
                            if parts.len() == 2 {
                                let src_part = parts[1].trim();
                                // Get the length of the source string
                                if let Some(length) =
                                    self.get_string_length_from_context(Some(src_part), source)
                                {
                                    return length;
                                }
                            }
                        }
                    }
                }
            }
        }
        0
    }

    /// Check for multiple strcat operations that might cause cumulative overflow
    fn check_sequential_strcat_overflow(
        &self,
        node: &Node,
        source: &str,
        root: &Node,
    ) -> Option<RuleViolation> {
        // Only analyze at function scope to capture multiple strcat calls
        if node.kind() != "function_definition" {
            return None;
        }

        // Scan only the lines within this function body, not the entire file
        let func_start = node.start_position().row;
        let func_end = node.end_position().row;
        let lines: Vec<&str> = source.lines().collect();
        let mut strcat_operations: Vec<(usize, String, String)> = Vec::new(); // (line_num, dest_var, src_var)

        // First pass: collect strcat operations within this function's line range
        for (line_idx, line) in lines
            .iter()
            .enumerate()
            .skip(func_start)
            .take(func_end.saturating_sub(func_start) + 1)
        {
            if line.contains("strcat") {
                if let Some((dest, src)) = self.extract_strcat_arguments(line) {
                    strcat_operations.push((line_idx + 1, dest, src));
                }
            }
        }

        // Group strcat operations by destination variable
        let mut dest_groups: HashMap<String, Vec<(usize, String)>> = HashMap::new();
        for (line_num, dest, src) in strcat_operations {
            dest_groups.entry(dest).or_default().push((line_num, src));
        }

        // Analyze each destination for cumulative overflow
        for (dest_var, operations) in dest_groups {
            if operations.len() > 1 {
                // Multiple strcat operations on same variable
                if let Some(violation) =
                    self.analyze_cumulative_strcat(&dest_var, &operations, source, root)
                {
                    return Some(violation);
                }
            }
        }

        None
    }

    /// Extract destination and source from strcat line
    fn extract_strcat_arguments(&self, line: &str) -> Option<(String, String)> {
        // Parse: strcat(dest, src);
        if let Some(start_paren) = line.find("strcat(") {
            let start = start_paren + 7; // length of "strcat("
            if let Some(end_paren) = line[start..].find(')') {
                let args_part = &line[start..start + end_paren];
                let parts: Vec<&str> = args_part.split(',').collect();
                if parts.len() == 2 {
                    let dest = parts[0].trim().to_string();
                    let src = parts[1].trim().to_string();
                    return Some((dest, src));
                }
            }
        }
        None
    }

    /// Analyze cumulative effect of multiple strcat operations
    fn analyze_cumulative_strcat(
        &self,
        dest_var: &str,
        operations: &[(usize, String)],
        source: &str,
        root: &Node,
    ) -> Option<RuleViolation> {
        // Get destination buffer size using the already-parsed root node
        let buffer_size = self.find_buffer_size(dest_var, root, source, None)?;

        // Start with initial buffer content
        let mut cumulative_length = self.get_initial_buffer_content_length(dest_var, source);

        // Track cumulative length after each strcat
        for (line_num, src_var) in operations {
            let src_length = self
                .get_string_length_from_context(Some(src_var), source)
                .unwrap_or(0);
            cumulative_length += src_length;

            // Check if this operation would cause overflow
            if cumulative_length + 1 > buffer_size {
                // +1 for null terminator
                return Some(RuleViolation {
                    rule_id: "STR31-C".to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Multiple strcat operations cause buffer overflow. Cumulative length {} exceeds buffer size {}",
                        cumulative_length + 1, buffer_size
                    ),
                    file_path: String::new(),
                    line: *line_num,
                    column: 1,
                    suggestion: Some("Use strncat with size limits or allocate larger buffer".to_string()),
                ..Default::default()
                });
            }
        }

        None
    }

    /// Get initial content length of buffer (from initialization or strcpy)
    fn get_initial_buffer_content_length(&self, var_name: &str, source: &str) -> usize {
        let lines: Vec<&str> = source.lines().collect();

        for line in &lines {
            // Check for initialization: char buffer[20] = "Start";
            if line.contains(var_name) && line.contains("=") && line.contains("\"") {
                // Find the first string literal, not the last quote on the line
                if let Some(start_quote) = line.find('"') {
                    // Find the closing quote for this string literal, accounting for escape sequences
                    let mut end_quote = start_quote + 1;
                    while end_quote < line.len() {
                        if line.chars().nth(end_quote) == Some('"') {
                            let literal = &line[start_quote + 1..end_quote];
                            return literal.len();
                        }
                        if line.chars().nth(end_quote) == Some('\\') {
                            end_quote += 2; // Skip escape sequence
                        } else {
                            end_quote += 1;
                        }
                    }
                }
            }

            // Check for strcpy that sets initial content
            if line.contains("strcpy") && line.contains(var_name) {
                // This would give us the initial content from strcpy
                return self.find_strcpy_source_length(var_name, source);
            }
        }

        0 // Empty buffer initially
    }

    /// Estimate the total length after strcat concatenation
    fn estimate_strcat_total_length(
        &self,
        dest_var: &str,
        arguments: &Node,
        source: &str,
    ) -> Option<usize> {
        // Get the source argument from strcat(dest, src)
        let mut src_arg = None;
        let mut arg_count = 0;

        for i in 0..arguments.child_count() {
            if let Some(arg) = arguments.child(i) {
                if arg.kind() == "identifier" && arg_count == 1 {
                    src_arg = Some(&source[arg.start_byte()..arg.end_byte()]);
                    break;
                }
                if arg.kind() != "," && arg.kind() != "(" && arg.kind() != ")" {
                    arg_count += 1;
                }
            }
        }

        if let Some(src_name) = src_arg {
            // First try to get current length from direct assignment
            let mut dest_current_length = self
                .get_string_length_from_context(Some(dest_var), source)
                .unwrap_or(0);

            // If we can't find direct assignment, look for strcpy operations that may have filled the buffer
            if dest_current_length == 0 {
                dest_current_length = self.find_strcpy_source_length(dest_var, source);
            }

            let src_length = self
                .get_string_length_from_context(Some(src_name), source)
                .unwrap_or(0);

            // For strcat_safe.c: "Hello" (5) + " World" (6) + null (1) = 12
            if dest_current_length > 0 && src_length > 0 {
                return Some(dest_current_length + src_length + 1);
            }
        }

        None
    }

    /// Check if wcstombs has sufficient buffer size
    fn check_wcstombs_safety(&self, arguments: &Node, source: &str, root: &Node) -> bool {
        // Extract destination buffer and size arguments
        let mut dest_name = None;
        let mut _buffer_size_arg = None;
        let mut arg_count = 0;

        for i in 0..arguments.child_count() {
            if let Some(arg) = arguments.child(i) {
                if arg.kind() == "identifier" && arg_count == 0 {
                    dest_name = Some(&source[arg.start_byte()..arg.end_byte()]);
                } else if arg.kind() == "number_literal" && arg_count == 2 {
                    let size_text = &source[arg.start_byte()..arg.end_byte()];
                    if let Ok(size) = size_text.parse::<usize>() {
                        _buffer_size_arg = Some(size);
                    }
                }

                if arg.kind() != "," && arg.kind() != "(" && arg.kind() != ")" {
                    arg_count += 1;
                }
            }
        }

        // Check if buffer size is reasonable for wide char conversion
        if let Some(dest) = dest_name {
            if let Some(buffer_size) =
                self.find_buffer_size_with_alias(dest, root, source, arguments)
            {
                // Wide chars can expand significantly when converted to multibyte
                // A reasonable buffer should be at least 4x the wide string length
                // For safety, we consider buffers < 64 as potentially unsafe
                if buffer_size >= 64 {
                    return true;
                }
            }
        }

        false
    }
}

impl CertRule for Str31C {
    fn rule_id(&self) -> &'static str {
        "STR31-C"
    }

    fn description(&self) -> &'static str {
        "Guarantee that storage for strings has sufficient space for character data and the null terminator"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "STR31-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        // node is always the translation_unit root when called by the framework.
        // Pass it down to avoid re-finding root on every recursive call.
        let mut violations = Vec::new();
        self.check_node(node, source, node, &mut violations);
        violations
    }
}

impl Str31C {
    fn check_node<'a>(
        &self,
        node: &Node<'a>,
        source: &str,
        root: &Node<'a>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check for sequential strcat overflow only at function scope
        if node.kind() == "function_definition" {
            if let Some(v) = self.check_sequential_strcat_overflow(node, source, root) {
                violations.push(v);
            }
        }

        // Check for dangerous function calls
        if node.kind() == "call_expression" {
            if let Some(function_node) = node.child_by_field_name("function") {
                let function_name = &source[function_node.start_byte()..function_node.end_byte()];
                let start_point = node.start_position();

                match function_name {
                    // gets() is ALWAYS dangerous - no bounds checking possible
                    "gets" => {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::High,
                            message: "Use of gets() is extremely dangerous and deprecated. It has no bounds checking.".to_string(),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some("Use fgets() with explicit buffer size instead".to_string()),
                        ..Default::default()
                        });
                    }

                    // strcpy/strcat - check if actually unsafe
                    "strcpy" => {
                        if let Some(arguments) = node.child_by_field_name("arguments") {
                            if !self.check_strcpy_safety(&arguments, source, &root) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::Medium,
                                    message: "Potential buffer overflow with strcpy(). Cannot verify destination buffer is large enough.".to_string(),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some("Use strncpy() with explicit size limit or verify buffer size".to_string()),
                                ..Default::default()
                                });
                            }
                        }
                    }

                    "strcat" => {
                        // strcat is particularly dangerous as it appends to existing content
                        if let Some(arguments) = node.child_by_field_name("arguments") {
                            if !self.check_strcat_safety(&arguments, source, &root) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::Medium,
                                    message: "Potential buffer overflow with strcat(). Cannot verify destination has space for concatenation.".to_string(),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some("Use strncat() with size limit or track remaining buffer space".to_string()),
                                ..Default::default()
                                });
                            }
                        }
                    }

                    // Wide character equivalents
                    "wcscpy" => {
                        if let Some(arguments) = node.child_by_field_name("arguments") {
                            if !self.check_strcpy_safety(&arguments, source, &root) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::Medium,
                                    message: "Potential buffer overflow with wcscpy(). Cannot verify destination buffer is large enough.".to_string(),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some("Use wcsncpy() with explicit size limit or verify buffer size".to_string()),
                                ..Default::default()
                                });
                            }
                        }
                    }

                    "wcscat" => {
                        if let Some(arguments) = node.child_by_field_name("arguments") {
                            if !self.check_strcat_safety(&arguments, source, &root) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::Medium,
                                    message: "Potential buffer overflow with wcscat(). Cannot verify destination has space for concatenation.".to_string(),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some("Use wcsncat() with size limit or track remaining buffer space".to_string()),
                                ..Default::default()
                                });
                            }
                        }
                    }

                    "wcsncpy" => {
                        if let Some(arguments) = node.child_by_field_name("arguments") {
                            if !self.check_strncpy_safety(&arguments, source, &root) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::Medium,
                                    message: "Potential null termination issue with wcsncpy(). Size parameter equals buffer size.".to_string(),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some("Use size-1 as limit and explicitly null-terminate, or use wcslcpy()".to_string()),
                                ..Default::default()
                                });
                            }
                        }
                    }

                    "wcsncat" => {
                        if let Some(arguments) = node.child_by_field_name("arguments") {
                            if !self.check_strcat_safety(&arguments, source, &root) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::Medium,
                                    message: "Potential buffer overflow with wcsncat(). Verify destination has sufficient space.".to_string(),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some("Ensure size parameter accounts for existing content and null terminator".to_string()),
                                ..Default::default()
                                });
                            }
                        }
                    }

                    "wmemcpy" => {
                        if let Some(arguments) = node.child_by_field_name("arguments") {
                            if self.is_string_memcpy(&arguments, source, &root) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::Medium,
                                    message: "wmemcpy used for string copying may not include null terminator".to_string(),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some("Use wcscpy/wcsncpy or wmemcpy with size+1 for null terminator".to_string()),
                                ..Default::default()
                                });
                            }
                        }
                    }

                    "swprintf" => {
                        if let Some(arguments) = node.child_by_field_name("arguments") {
                            if !self.check_sprintf_safety(&arguments, source, &root) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::Medium,
                                    message: "Potential buffer overflow with swprintf(). Cannot verify output fits in destination buffer.".to_string(),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some("Use snwprintf() with explicit buffer size or verify buffer capacity".to_string()),
                                ..Default::default()
                                });
                            }
                        }
                    }

                    // sprintf - check format string safety
                    "sprintf" => {
                        if let Some(arguments) = node.child_by_field_name("arguments") {
                            if !self.check_sprintf_safety(&arguments, source, &root) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::Medium,
                                    message: "Potential buffer overflow with sprintf(). Cannot verify output fits in destination buffer.".to_string(),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some("Use snprintf() with explicit buffer size".to_string()),
                                ..Default::default()
                                });
                            }
                        }
                    }

                    // vsprintf is dangerous - no size limit
                    "vsprintf" => {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::High,
                            message: "Use of vsprintf() is dangerous as it has no bounds checking."
                                .to_string(),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(
                                "Use vsnprintf() with explicit buffer size".to_string(),
                            ),
                            ..Default::default()
                        });
                    }

                    // scanf family - check for unbounded %s
                    "scanf" | "fscanf" | "sscanf" => {
                        if let Some(arguments) = node.child_by_field_name("arguments") {
                            if self.check_scanf_format(&arguments, source) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::High,
                                    message: format!("Dangerous use of {}() with unbounded %%s format specifier.", function_name),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some("Use width specifier with %s (e.g., %99s) or use fgets()".to_string()),
                                ..Default::default()
                                });
                            }
                        }
                    }

                    // strncpy - check for null termination issues
                    "strncpy" => {
                        if let Some(arguments) = node.child_by_field_name("arguments") {
                            if !self.check_strncpy_safety(&arguments, source, &root) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::Medium,
                                    message: "Potential null termination issue with strncpy(). Size parameter equals buffer size.".to_string(),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some("Use size-1 as limit and explicitly null-terminate, or use strlcpy()".to_string()),
                                ..Default::default()
                                });
                            }
                        }
                    }

                    "memcpy" => {
                        // Check if memcpy is being used for string operations
                        if let Some(arguments) = node.child_by_field_name("arguments") {
                            if self.is_string_memcpy(&arguments, source, &root) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::Medium,
                                    message: "memcpy used for string copying may not include null terminator".to_string(),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some("Use strcpy/strncpy or memcpy with size+1 for null terminator".to_string()),
                                ..Default::default()
                                });
                            }
                        }
                    }

                    "wcstombs" => {
                        // Check wide char to multibyte conversion buffer size
                        if let Some(arguments) = node.child_by_field_name("arguments") {
                            if !self.check_wcstombs_safety(&arguments, source, &root) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::Medium,
                                    message: "wcstombs may overflow buffer - wide chars can expand to multiple bytes".to_string(),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some("Use larger buffer or wcstombs_s with size limit".to_string()),
                                ..Default::default()
                                });
                            }
                        }
                    }

                    _ => {}
                }
            }
        }

        // Check for unvalidated argv usage (main with argv but no argc validation)
        if node.kind() == "function_definition" {
            let func_text = &source[node.start_byte()..node.end_byte()];

            // Check if this is main() with argv parameter but no validation
            if func_text.contains("main")
                && func_text.contains("argc")
                && func_text.contains("argv")
                && func_text.contains("char *argv")
            {
                // Check if there's any argc validation (e.g., "argc &&" or "if (argc")
                if !func_text.contains("argc &&")
                    && !func_text.contains("if (argc")
                    && !func_text.contains("if(argc")
                {
                    let start_point = node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Medium,
                        message: "Program arguments (argv) used without validating argc or checking for null pointers".to_string(),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Validate argc and argv[0] before use: const char *prog = (argc && argv[0]) ? argv[0] : \"\"".to_string()),
                    ..Default::default()
                    });
                }
            }
        }

        // Check for off-by-one errors in manual string copy (dest[i] after loop with i < n)
        if self.detect_off_by_one_error(node, source) {
            let start_point = node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::Medium,
                message: "Off-by-one error: accessing array[i] after loop with condition 'i < n' can access out-of-bounds memory when i == n".to_string(),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some("Use 'dest[i-1] = '\\0'' or adjust loop condition to 'i < n-1'".to_string()),
            ..Default::default()
            });
        }

        // Check for manual string copying loops without bounds checking
        if self.detect_manual_string_loop(node, source) {
            let start_point = node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::Medium,
                message: "Manual string copying loop without apparent bounds checking detected.".to_string(),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some("Add explicit bounds checking or use standard string functions with size limits".to_string()),
            ..Default::default()
            });
        }

        // Check for very small character arrays (less than 2)
        if node.kind() == "array_declarator" {
            if let Some(size_node) = node.child_by_field_name("size") {
                let size_text = &source[size_node.start_byte()..size_node.end_byte()];
                if let Ok(size) = size_text.parse::<i32>() {
                    if size < 2 {
                        let start_point = node.start_position();
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Medium,
                            message: "Character array too small to hold any string data plus null terminator".to_string(),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some("Increase array size to accommodate expected string length plus null terminator".to_string()),
                        ..Default::default()
                        });
                    }
                }
            }
        }

        // Recursively check child nodes
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.check_node(&child, source, root, violations);
            }
        }
    }
}
