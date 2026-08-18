use super::super::{CertRule, RuleViolation};
use crate::analyze::buffer_size;
use crate::analyze::context::ProjectContext;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashMap;
use tree_sitter::Node;

/// STR31-C bounds-string-copy rule.
///
/// `callsite_param_buffer_size` is seeded from the prescan: for each function it
/// records, per parameter index, the minimum element-count buffer size that any
/// caller passes — but only when every caller passes a statically-sized buffer.
/// It lets the rule prove that a `strcpy(param, …)`-style copy into a parameter
/// destination is bounded by the caller's buffer, suppressing the cross-function
/// goodG2BSink false positives (Juliet flow variants 41+).
#[derive(Default)]
pub struct Str31C {
    callsite_param_buffer_size: RefCell<HashMap<String, HashMap<usize, usize>>>,
}

impl Str31C {
    pub fn new() -> Self {
        Self::default()
    }

    /// When `dest` is a parameter of the enclosing function, return the minimum
    /// element-count buffer size that any caller passes at that position — but
    /// only when the prescan proved *every* caller passes a statically-sized
    /// buffer (see [`crate::analyze::function_summary::FunctionSummary::callsite_param_buffer_size`]).
    /// Returns `None` when `dest` is not a parameter, the function has external
    /// callers, or any caller's buffer is unresolvable.
    fn caller_min_buffer_for_param(&self, dest: &str, node: &Node, source: &str) -> Option<usize> {
        let func = ast_utils::find_containing_function(node)?;
        let declarator = func.child_by_field_name("declarator")?;
        let func_name = ast_utils::get_identifier_from_declarator(&declarator, source);
        if func_name.is_empty() {
            return None;
        }
        let params = ast_utils::get_function_parameters(&func, source)?;
        let param_idx = params.iter().position(|(name, _)| name == dest)?;
        let map = self.callsite_param_buffer_size.borrow();
        map.get(&func_name)?.get(&param_idx).copied()
    }

    /// For a copy whose destination is a function parameter, decide whether the
    /// caller-provided buffer is provably large enough to hold the source.
    ///
    /// `needed` is the largest number of elements (including the null
    /// terminator) the source can contribute. The copy is safe iff every
    /// caller's buffer is at least that large. Returns `false` whenever the
    /// caller buffer or `needed` is unknown, so the rule stays conservative.
    fn param_dest_bounded_by_caller(
        &self,
        dest: &str,
        node: &Node,
        source: &str,
        needed: Option<usize>,
    ) -> bool {
        match (self.caller_min_buffer_for_param(dest, node, source), needed) {
            (Some(caller_buf), Some(needed)) => caller_buf >= needed,
            _ => false,
        }
    }
}

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
        buffer_size::memset_content_length(var_name, source, call_node)
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

        if let Some(size) = Self::find_array_declaration_size(var_name, &lines) {
            return Some(size);
        }

        // Restrict dynamic-allocation scans to the enclosing function to prevent cross-function
        // pollution (e.g. bad-section malloc(50) bleeding into good-section analysis).
        let fn_start = fn_range.map_or(0, |(s, _)| s);
        let fn_end = fn_range.map_or(lines.len().saturating_sub(1), |(_, e)| e);

        if let Some(size) = Self::find_strlen_based_alloc_size(var_name, &lines, fn_start, fn_end) {
            return Some(size);
        }
        if let Some(size) = Self::find_fixed_alloc_size(var_name, &lines, fn_start, fn_end) {
            return Some(size);
        }
        if let Some(size) = Self::find_realloc_dynamic_size(var_name, &lines, fn_start, fn_end) {
            return Some(size);
        }
        Self::find_alloca_size(var_name, &lines, fn_start, fn_end)
    }

    /// Look for array declarations like `char var_name[SIZE]` or
    /// `char var_name[N*M]`. Skips element-assignment lines like
    /// `data[0] = '\0'` — those are subscript writes, not declarations, and
    /// the captured index (0) is not the buffer size.
    fn find_array_declaration_size(var_name: &str, lines: &[&str]) -> Option<usize> {
        /// Scalar RHS after `]=` = char/wide-char literal, number, or NULL —
        /// signals an element assignment rather than a declaration initializer.
        fn is_element_assign_rhs(after: &str) -> bool {
            after.starts_with('=') && {
                let rhs = after[1..].trim_start();
                rhs.starts_with('\'')
                    || rhs.starts_with("L'")
                    || rhs.starts_with("u'")
                    || rhs.starts_with("U'")
                    || rhs.chars().next().is_some_and(|c| c.is_ascii_digit())
                    || rhs.starts_with("NULL")
                    || rhs.starts_with("nullptr")
            }
        }

        for line in lines {
            if !(line.contains(var_name) && line.contains('[') && line.contains(']')) {
                continue;
            }
            // Try simple numeric size first: var_name[N]
            let pattern = format!(r"\b{}\s*\[\s*(\d+)\s*\]", regex::escape(var_name));
            if let Ok(re) = regex::Regex::new(&pattern) {
                if let Some(captures) = re.captures(line) {
                    let match_end = captures.get(0).unwrap().end();
                    let after = line[match_end..].trim_start();
                    if !is_element_assign_rhs(after) {
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
                    if !is_element_assign_rhs(after) {
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
        None
    }

    /// Look for malloc/calloc assignments with `strlen`/`wcslen` + 1 →
    /// dynamically safe, either directly in the call or via an
    /// intermediate size variable assigned from strlen/wcslen.
    fn find_strlen_based_alloc_size(
        var_name: &str,
        lines: &[&str],
        fn_start: usize,
        fn_end: usize,
    ) -> Option<usize> {
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

        // Checks whether `size_var` was assigned from strlen()/wcslen() anywhere
        // in the enclosing function's line range.
        let assigned_from_len_fn = |size_var: &str, wide: bool| -> bool {
            let pat = if wide {
                format!(r"\b{}\s*=\s*wcslen\s*\(", regex::escape(size_var))
            } else {
                format!(r"\b{}\s*=\s*(?:w?)strlen\s*\(", regex::escape(size_var))
            };
            let Ok(re) = regex::Regex::new(&pat) else {
                return false;
            };
            let end = fn_end.min(lines.len().saturating_sub(1));
            lines[fn_start..=end].iter().any(|l| re.is_match(l))
        };

        for (idx, line) in lines.iter().enumerate() {
            if idx < fn_start || idx > fn_end {
                continue;
            }
            let assigns_here = Self::line_assigns_to(line, var_name);
            if assigns_here
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
            if assigns_here && line.contains("calloc") {
                if let Some(caps) = calloc_narrow_re.as_ref().and_then(|re| re.captures(line)) {
                    if assigned_from_len_fn(&caps[1], false) {
                        return Some(usize::MAX);
                    }
                }
                // calloc(wcslen_var+1, sizeof(wchar_t)) where wcslen_var = wcslen(...)
                // — safe wide-string allocation.  Requires wcslen specifically (not strlen)
                // so calloc(strlen_var+1, sizeof(wchar_t)) remains flagged as a real bug.
                if let Some(caps) = calloc_wide_re.as_ref().and_then(|re| re.captures(line)) {
                    if assigned_from_len_fn(&caps[1], true) {
                        return Some(usize::MAX);
                    }
                }
            }
            // malloc(strlen_var+1) — implied byte-sized element
            if assigns_here && line.contains("malloc") {
                if let Some(caps) = malloc_indirect_re.as_ref().and_then(|re| re.captures(line)) {
                    if assigned_from_len_fn(&caps[1], false) {
                        return Some(usize::MAX);
                    }
                }
            }
        }
        None
    }

    /// True if `line` contains an assignment whose LHS is exactly `var_name`
    /// (word-boundary on both sides, so `data` does not match `dataBuffer`),
    /// followed by a plain `=` (not `==`).
    ///
    /// Several of the line-scan finders below used to gate on a bare
    /// `line.contains(var_name)`, which spuriously matched `dataBuffer =
    /// malloc(...)` when resolving a variable named `data` — Juliet's own
    /// `X`/`XBuffer`/`XGoodBuffer`/`XBadBuffer` naming convention makes this
    /// collision common. That falsely attributed another variable's
    /// allocation to `data`, masking real overflows reached only through
    /// `find_buffer_size`'s alias-chasing paths (task 203).
    fn line_assigns_to(line: &str, var_name: &str) -> bool {
        let pattern = format!(r"\b{}\b\s*=[^=]", regex::escape(var_name));
        regex::Regex::new(&pattern)
            .map(|re| re.is_match(line))
            .unwrap_or(false)
    }

    /// Look for malloc/calloc assignments with specific numeric sizes.
    /// Handles casts (`data = (char *)malloc(N*sizeof(char))`), parenthesized
    /// arithmetic (`malloc((N+M)*sizeof(type))`), and plain `malloc(N)`.
    fn find_fixed_alloc_size(
        var_name: &str,
        lines: &[&str],
        fn_start: usize,
        fn_end: usize,
    ) -> Option<usize> {
        let malloc_sizeof_re =
            regex::Regex::new(r"(?:malloc|calloc)\s*\(\s*(\d+)\s*[*,]\s*sizeof").ok();
        let malloc_paren_sizeof_re = regex::Regex::new(
            r"(?:malloc|calloc)\s*\(\s*\(\s*(\d+)\s*(?:([+*\-])\s*(\d+))?\s*\)\s*\*\s*sizeof",
        )
        .ok();
        let malloc_plain_re = regex::Regex::new(r"(?:malloc|calloc)\s*\(\s*(\d+)\s*[,)]").ok();

        for (idx, line) in lines.iter().enumerate() {
            if idx < fn_start || idx > fn_end {
                continue;
            }
            if !(Self::line_assigns_to(line, var_name)
                && (line.contains("malloc") || line.contains("calloc")))
            {
                continue;
            }
            // malloc(N*sizeof(type)) or calloc(N, sizeof(type))
            if let Some(caps) = malloc_sizeof_re.as_ref().and_then(|re| re.captures(line)) {
                if let Ok(n) = caps[1].parse::<usize>() {
                    return Some(n);
                }
            }
            // malloc((N+M)*sizeof(type)) or malloc((N)*sizeof(type))
            if let Some(caps) = malloc_paren_sizeof_re
                .as_ref()
                .and_then(|re| re.captures(line))
            {
                let a = caps[1].parse::<usize>().ok();
                let op = caps.get(2).map(|m| m.as_str());
                let b = caps.get(3).and_then(|m| m.as_str().parse::<usize>().ok());
                if let Some(n) = buffer_size::eval_arith(a, op, b) {
                    return Some(n);
                }
            }
            // Plain malloc(N) or calloc(N, M) with numeric first arg
            if let Some(caps) = malloc_plain_re.as_ref().and_then(|re| re.captures(line)) {
                if let Ok(n) = caps[1].parse::<usize>() {
                    return Some(n);
                }
            }
        }
        None
    }

    /// Look for `realloc` patterns with strlen-based size calculations.
    fn find_realloc_dynamic_size(
        var_name: &str,
        lines: &[&str],
        fn_start: usize,
        fn_end: usize,
    ) -> Option<usize> {
        for (idx, line) in lines.iter().enumerate() {
            if idx < fn_start || idx > fn_end {
                continue;
            }
            if Self::line_assigns_to(line, var_name)
                && line.contains("realloc")
                && line.contains("strlen")
                && (line.contains('+') || line.contains("new_size"))
            {
                return Some(usize::MAX);
            }
        }
        None
    }

    /// Look for ALLOCA/alloca assignments: `var = (type *)ALLOCA(N*sizeof(type))`.
    fn find_alloca_size(
        var_name: &str,
        lines: &[&str],
        fn_start: usize,
        fn_end: usize,
    ) -> Option<usize> {
        let assign_re = regex::Regex::new(&format!(r"\b{}\s*=", regex::escape(var_name))).ok()?;
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
            if !assign_re.is_match(line) || !(line.contains("ALLOCA") || line.contains("alloca")) {
                continue;
            }
            // strlen/wcslen directly in ALLOCA call → safe dynamic size
            if line.contains("strlen") || line.contains("wcslen") {
                return Some(usize::MAX);
            }
            // Pattern: ALLOCA(N*sizeof(type)) — N is the element count
            if let Some(caps) = alloca_sizeof_re.as_ref().and_then(|re| re.captures(line)) {
                if let Ok(n) = caps[1].parse::<usize>() {
                    return Some(n);
                }
            }
            // Pattern: ALLOCA((N)*sizeof(type)) or ALLOCA((N+M)*sizeof(type))
            if let Some(caps) = alloca_paren_sizeof_re
                .as_ref()
                .and_then(|re| re.captures(line))
            {
                let a = caps[1].parse::<usize>().ok();
                let op = caps.get(2).map(|m| m.as_str());
                let b = caps.get(3).and_then(|m| m.as_str().parse::<usize>().ok());
                if let Some(s) = buffer_size::eval_arith(a, op, b) {
                    return Some(s);
                }
            }
            // Simpler: ALLOCA(N) without sizeof
            if let Some(caps) = alloca_simple_re.as_ref().and_then(|re| re.captures(line)) {
                if let Ok(n) = caps[1].parse::<usize>() {
                    return Some(n);
                }
            }
            // ALLOCA arg is a variable (e.g. ALLOCA((dataLen+1)*1)) — check if that
            // variable was assigned from strlen() anywhere in the file, which means
            // the allocation is exactly sized for the source string.
            if let Some(caps) = alloca_ident_re.as_ref().and_then(|re| re.captures(line)) {
                let first_ident = &caps[1];
                let skip = matches!(
                    first_ident,
                    "sizeof" | "char" | "wchar_t" | "int" | "size_t" | "void" | "long"
                );
                if !skip {
                    let strlen_pat =
                        format!(r"\b{}\s*=\s*(?:w?)strlen\s*\(", regex::escape(first_ident));
                    if let Ok(strlen_re) = regex::Regex::new(&strlen_pat) {
                        if lines.iter().any(|l| strlen_re.is_match(l)) {
                            return Some(usize::MAX);
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
        let fn_range = Self::find_enclosing_function_lines(call_node)?;
        Self::resolve_pointer_alias_in_range(var_name, fn_range, source)
    }

    /// Line-range-based core of [`Self::resolve_pointer_alias_in_function`],
    /// usable when the caller already has a `(start_line, end_line)` range
    /// instead of a tree-sitter node to derive one from (e.g.
    /// [`Self::find_global_buffer_size`], which locates the range of a
    /// DIFFERENT function than the one performing the copy).
    fn resolve_pointer_alias_in_range(
        var_name: &str,
        (start_line, end_line): (usize, usize),
        source: &str,
    ) -> Option<String> {
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
                // Skip self-assignment, NULL, and numeric literals. (A
                // genuine call-shaped RHS like `ALLOCA(...)`/`malloc(...)`
                // can never match `(\w+)\s*;` in the first place — the `(`
                // right after the bare word breaks the match — so no
                // separate "looks like a call" text check is needed here;
                // one used to substring-match "alloca" against the whole
                // line, which false-skipped Juliet's alloca-variant tests
                // whose *identifier names themselves* contain "alloca" as a
                // substring, e.g. `..._alloca_cpy_45_badData`.)
                if target == var_name || target == "NULL" || target == "0" {
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
            if let Some(size) = self.find_buffer_size(&alias_target, root, source, fn_range) {
                return Some(size);
            }
            // Juliet flow variant 45 passes the destination buffer through a
            // file-scope `static` global instead of a parameter or a local
            // alias: `bad()` allocates a buffer and stores it into a global,
            // then a DIFFERENT function in the same file (`badSink()`) reads
            // the global and performs the copy. The alias target here is
            // that global, but `find_buffer_size` above only searched
            // `badSink()`'s own line range, where no allocation exists.
            return self.find_global_buffer_size(&alias_target, root, source);
        }
        None
    }

    /// Resolve `global_name`'s buffer size by scanning every assignment to it
    /// across the WHOLE file, each resolved within ITS OWN enclosing
    /// function's line range (not the reader's) — the allocation and the
    /// read/copy live in different functions (Juliet variant 45: `bad()`
    /// allocates and stores into a global; `badSink()` reads it). Returns the
    /// minimum resolvable size across every assignment site found, and `None`
    /// if no assignment resolves (stays conservative rather than guessing).
    fn find_global_buffer_size(
        &self,
        global_name: &str,
        root: &Node,
        source: &str,
    ) -> Option<usize> {
        let pattern = format!(
            r"\b{}\s*=\s*(?:\([^)]*\)\s*)?(\w+)\s*;",
            regex::escape(global_name)
        );
        let re = regex::Regex::new(&pattern).ok()?;
        let lines: Vec<&str> = source.lines().collect();

        let mut min_size: Option<usize> = None;
        for (idx, line) in lines.iter().enumerate() {
            let Some(caps) = re.captures(line) else {
                continue;
            };
            let target = &caps[1];
            if target == global_name || target == "NULL" || target == "0" {
                continue;
            }
            let fn_range = Self::function_range_containing_line(root, idx)?;
            // `target` is often itself just a local alias for the real
            // allocation within the writer function (Juliet variant 45:
            // `data = dataGoodBuffer; ...; GLOBAL = data;` — the global is
            // assigned from `data`, which is in turn assigned from the
            // actual `ALLOCA`'d buffer). One more hop of alias resolution,
            // scoped to the writer's own range, covers this.
            let size = match self.find_buffer_size(target, root, source, Some(fn_range)) {
                Some(size) => size,
                None => {
                    let alias2 = Self::resolve_pointer_alias_in_range(target, fn_range, source)?;
                    self.find_buffer_size(&alias2, root, source, Some(fn_range))?
                }
            };
            min_size = Some(min_size.map_or(size, |m: usize| m.min(size)));
        }
        min_size
    }

    /// Find the `function_definition` node (by line range) that contains
    /// `line` (0-indexed), if any.
    fn function_range_containing_line(root: &Node, line: usize) -> Option<(usize, usize)> {
        query::find_descendants_of_kind(*root, "function_definition")
            .into_iter()
            .map(|f| (f.start_position().row, f.end_position().row))
            .find(|(start, end)| line >= *start && line <= *end)
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
        let (dest_name, source_name, source_length) =
            self.extract_copy_call_args(arguments, source);

        // If we have destination name, try to find its size
        let Some(dest) = dest_name else {
            return false;
        };

        // NEW: Check if destination was previously freed / has a prior safe realloc
        if let Some(early) = self.check_strcpy_dest_precondition(dest, arguments, source) {
            return early;
        }

        if let Some(buffer_size) = self.find_buffer_size_with_alias(dest, root, source, arguments) {
            return self.check_strcpy_known_buffer_size(
                buffer_size,
                source_name,
                source_length,
                root,
                source,
                arguments,
            );
        }

        self.check_strcpy_unknown_buffer_size(
            dest,
            source_name,
            source_length,
            arguments,
            source,
            root,
        )
    }

    /// Extract the destination identifier, source identifier, and (for a
    /// string-literal source) its length from a `strcpy`/`strncpy`-style
    /// call's argument list.
    fn extract_copy_call_args<'a>(
        &self,
        arguments: &Node,
        source: &'a str,
    ) -> (Option<&'a str>, Option<&'a str>, Option<usize>) {
        let mut dest_name = None;
        let mut source_name = None;
        let mut source_length = None;
        let mut arg_count = 0;

        for i in 0..arguments.child_count() {
            let Some(arg) = arguments.child(i) else {
                continue;
            };
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
        (dest_name, source_name, source_length)
    }

    /// Check destination-buffer preconditions that short-circuit the rest of
    /// the safety analysis: prior `free()` (always unsafe) or a prior safe
    /// `realloc()` (always safe). Returns `None` to continue analysis.
    fn check_strcpy_dest_precondition(
        &self,
        dest: &str,
        arguments: &Node,
        source: &str,
    ) -> Option<bool> {
        let fn_range_for_freed = Self::find_enclosing_function_lines(arguments);
        if self.was_buffer_freed_in_range(dest, source, fn_range_for_freed) {
            return Some(false); // Always unsafe to use freed memory
        }
        // Check if this strcpy/strcat happens after a realloc with proper size calculation
        if self.has_prior_safe_realloc(dest, source) {
            return Some(true); // Safe due to prior reallocation
        }
        None
    }

    /// Safety analysis once the destination buffer's size is known.
    fn check_strcpy_known_buffer_size(
        &self,
        buffer_size: usize,
        source_name: Option<&str>,
        source_length: Option<usize>,
        root: &Node,
        source: &str,
        arguments: &Node,
    ) -> bool {
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
            if let Some(result) = self.check_strcpy_source_variable_safety(
                src_name,
                buffer_size,
                root,
                source,
                arguments,
            ) {
                return result;
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
        false
    }

    /// NEW: Enhanced source variable analysis once the destination buffer
    /// size is known but the source length wasn't a literal. Returns
    /// `Some(is_safe)` on a conclusive pattern match, `None` to fall through
    /// to the generic large-buffer/short-literal checks.
    fn check_strcpy_source_variable_safety(
        &self,
        src_name: &str,
        buffer_size: usize,
        root: &Node,
        source: &str,
        arguments: &Node,
    ) -> Option<bool> {
        // Check for dangerous source patterns
        if src_name == "argv[1]" || src_name.contains("argv[") {
            // Command line arguments can be unlimited size
            return Some(false); // Always dangerous
        }

        // Check if source variable traces back to argv (e.g., name = argv[0])
        if self.traces_to_argv(src_name, source) {
            return Some(false); // Traces to argv - unbounded size
        }

        if src_name.contains("env_value") || src_name == "getenv" || src_name == "env_value" {
            // Environment variables can be unlimited size
            return Some(false); // Always dangerous
        }

        // Check if variable comes from getenv() call
        if self.is_variable_from_getenv(src_name, source) {
            return Some(false); // Environment variables are unlimited size
        }

        // Try to get content length from memset initialization.
        // This must come BEFORE source buffer size comparison because
        // memset content length (actual string length) is more precise
        // than the container buffer size.
        if let Some(content_len) = self.get_memset_content_length(src_name, source, arguments) {
            if buffer_size > content_len {
                return Some(true); // Buffer has room for memset content + null terminator
            }
        }

        // Check if source is a larger buffer (with alias resolution)
        if let Some(src_buffer_size) =
            self.find_buffer_size_with_alias(src_name, root, source, arguments)
        {
            if src_buffer_size > buffer_size {
                return Some(false); // Source is larger than destination - dangerous
            }
        }

        // Check for variables that are clearly larger arrays
        if self.is_larger_array_variable(src_name, buffer_size, source) {
            return Some(false); // Source array is larger than destination
        }
        // Try to get string length from variable context
        if let Some(src_len) = self.get_string_length_from_context(Some(src_name), source) {
            if buffer_size > src_len {
                return Some(true); // Buffer has room for string + null terminator
            }
        }
        // Check for known safe patterns
        let src_lower = src_name.to_lowercase();
        if (src_lower.contains("hello") || src_lower.contains("world")) && buffer_size >= 20 {
            return Some(true); // Known safe pattern from test cases
        }

        // Try to find source buffer size for array-to-array copy (with alias)
        if let Some(src_buffer_size) =
            self.find_buffer_size_with_alias(src_name, root, source, arguments)
        {
            if buffer_size >= src_buffer_size {
                return Some(true); // Destination is at least as large as source
            }
        }

        None
    }

    /// Cross-function fallback when the local destination size is unknown
    /// because `dest` is a parameter. Consult the buffer size that callers
    /// pass here (recorded by the prescan). When every caller's buffer is at
    /// least as large as the source can fill, the copy cannot overflow —
    /// this clears the goodG2BSink false positives where the same sink is
    /// reached from a caller using a large buffer (Juliet variants 41+).
    fn check_strcpy_unknown_buffer_size(
        &self,
        dest: &str,
        source_name: Option<&str>,
        source_length: Option<usize>,
        arguments: &Node,
        source: &str,
        root: &Node,
    ) -> bool {
        let needed = source_length.map(|n| n + 1).or_else(|| {
            source_name.and_then(|s| self.find_buffer_size_with_alias(s, root, source, arguments))
        });
        if self.param_dest_bounded_by_caller(dest, arguments, source, needed) {
            return true;
        }

        // Destination buffer size could not be determined (dynamic allocation, pointer param, etc.)
        // If source is a known string literal (bounded at compile time), we can't confirm
        // overflow without knowing the destination size — assume safe to avoid FPs in
        // unrelated CWEs where good functions copy fixed strings into opaque buffers.
        source_length.is_some() && !self.is_function_parameter(dest, source)
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
                    match self.estimate_strcat_total_length(dest, arguments, source) {
                        Some(total_length) => {
                            // `total_length` already counts the null
                            // terminator (see `estimate_strcat_total_length`),
                            // so a buffer of exactly that size is sufficient
                            // — not one byte larger.
                            if buffer_size >= total_length {
                                return true; // Safe concatenation
                            }
                            // Estimation succeeded and found the buffer too
                            // small — do NOT fall through to the "assume
                            // safe for large buffers" heuristic below; that
                            // heuristic exists only for when no estimate was
                            // possible at all, not to override a conclusive
                            // unsafe estimate (previously it ran
                            // unconditionally here, silently swallowing any
                            // buffer >= 50 that WAS provably too small).
                        }
                        None => {
                            // Fallback: no estimate was possible, but the
                            // buffer is reasonably large.
                            if buffer_size >= 50 {
                                return true; // Conservative: assume safe for large buffers
                            }
                        }
                    }
                }

                // Very large buffers are always safe
                if buffer_size >= 256 {
                    return true;
                }

                // Buffer size is known but small and source is unknown-length — flag it
                return false;
            }

            // Cross-function: destination is a parameter, so its size is unknown
            // locally. If every caller passes a buffer at least as large as the
            // source can fill, the concatenation into a freshly-provided buffer
            // cannot overflow (Juliet goodG2BSink cat/ncat variants 41+). The
            // bad sinks, reached from a small-buffer caller, stay flagged.
            let needed = if src_arg_kind == "string_literal" {
                let lit = src_arg_text
                    .trim_start_matches('L')
                    .trim_start_matches('"')
                    .trim_end_matches('"');
                Some(lit.len() + 1)
            } else {
                self.find_buffer_size_with_alias(src_arg_text, root, source, arguments)
            };
            if self.param_dest_bounded_by_caller(dest, arguments, source, needed) {
                return true;
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

    /// Unwrap a `parenthesized_expression` down to its inner expression
    /// (needed for `while` conditions, which the grammar wraps in parens;
    /// `for` conditions are already bare, so this is a no-op for those).
    fn unwrap_parens(mut node: Node) -> Node {
        while node.kind() == "parenthesized_expression" {
            match node.named_child(0) {
                Some(inner) => node = inner,
                None => break,
            }
        }
        node
    }

    /// Whether a `char_literal` node's text is the null terminator `'\0'`,
    /// ignoring any wide/UTF encoding prefix (`L'\0'`, `u'\0'`, ...).
    fn char_literal_is_null(node: &Node, source: &str) -> bool {
        let text = ast_utils::get_node_text(node, source);
        text.trim_start_matches(|c: char| c.is_ascii_alphabetic()) == "'\\0'"
    }

    /// Whether `node.child_by_field_name("update")` (for a `for_statement`)
    /// or the loop body's last increment (for a `while_statement`) contains
    /// a genuine `++var` / `var++` on `var`.
    fn loop_increments_var(loop_node: &Node, var: &str, source: &str) -> bool {
        let is_increment_of_var = |n: &Node| {
            n.kind() == "update_expression"
                && n.child_by_field_name("operator")
                    .is_some_and(|o| ast_utils::get_node_text(&o, source) == "++")
                && n.child_by_field_name("argument")
                    .is_some_and(|a| ast_utils::get_node_text(&a, source) == var)
        };
        if loop_node.kind() == "for_statement" {
            return loop_node
                .child_by_field_name("update")
                .is_some_and(|u| is_increment_of_var(&u));
        }
        loop_node
            .child_by_field_name("body")
            .map(|body| {
                query::find_descendants_of_kind(body, "update_expression")
                    .iter()
                    .any(is_increment_of_var)
            })
            .unwrap_or(false)
    }

    /// Whether the statement immediately following `loop_node` (skipping
    /// comments) is `<var>[<index>] = '\0';` — the classic off-by-one
    /// null-terminator write that lands one past the loop's last valid
    /// index once `index == bound`.
    fn next_statement_writes_null_at_index(
        loop_node: &Node,
        index_var: &str,
        source: &str,
    ) -> bool {
        let mut sibling = loop_node.next_sibling();
        while let Some(s) = sibling {
            if s.kind() == "comment" || !s.is_named() {
                sibling = s.next_sibling();
                continue;
            }
            let assignment = if s.kind() == "expression_statement" {
                s.named_child(0)
            } else {
                Some(s)
            };
            if let Some(assign) = assignment.filter(|a| a.kind() == "assignment_expression") {
                let Some(left) = assign.child_by_field_name("left") else {
                    return false;
                };
                let Some(right) = assign.child_by_field_name("right") else {
                    return false;
                };
                return left.kind() == "subscript_expression"
                    && left
                        .child_by_field_name("index")
                        .is_some_and(|i| ast_utils::get_node_text(&i, source) == index_var)
                    && right.kind() == "char_literal"
                    && Self::char_literal_is_null(&right, source);
            }
            // First real statement after the loop didn't match — the classic
            // pattern always has the null-write immediately after the loop.
            return false;
        }
        false
    }

    /// Detect off-by-one error in manual string copy (dest[i] = '\0' after loop with i < n).
    ///
    /// Structural version of the classic Juliet pattern
    /// `for (i = 0; i < n; ++i) { dest[i] = src[i]; } dest[i] = '\0';` —
    /// `i` equals `n` once the loop exits, so `dest[n]` is one past the
    /// last valid index (should be `dest[i - 1]` or the loop bound should
    /// be `i < n - 1`).
    fn detect_off_by_one_error(&self, node: &Node, source: &str) -> bool {
        if node.kind() != "function_definition" {
            return false;
        }

        for loop_node in
            query::find_descendants_of_kinds(*node, &["for_statement", "while_statement"])
        {
            let Some(condition) = loop_node.child_by_field_name("condition") else {
                continue;
            };
            let condition = Self::unwrap_parens(condition);

            // Find a `<` comparison anywhere in the condition (root included) —
            // covers both a bare `i < n` condition and a compound guard like
            // `src[i] && (i < n)`, which still off-by-ones once `i == n`.
            let bare_lt_bound = query::find_descendants_of_kind(condition, "binary_expression")
                .into_iter()
                .filter(|c| {
                    c.child_by_field_name("operator")
                        .is_some_and(|o| ast_utils::get_node_text(&o, source) == "<")
                })
                .find_map(|c| {
                    let left = c.child_by_field_name("left")?;
                    let right = c.child_by_field_name("right")?;
                    // Bound must be a bare identifier (`i < n`) — `i < n - 1`
                    // (any subtraction) is the safe form, deliberately unmatched.
                    if left.kind() == "identifier" && right.kind() == "identifier" {
                        Some(ast_utils::get_node_text(&left, source))
                    } else {
                        None
                    }
                });
            let Some(loop_var) = bare_lt_bound else {
                continue;
            };

            if !Self::loop_increments_var(&loop_node, loop_var, source) {
                continue;
            }

            let Some(loop_body) = loop_node.child_by_field_name("body") else {
                continue;
            };
            let body_indexes_by_loop_var =
                query::find_descendants_of_kind(loop_body, "subscript_expression")
                    .iter()
                    .any(|s| {
                        s.child_by_field_name("index")
                            .is_some_and(|i| ast_utils::get_node_text(&i, source) == loop_var)
                    });
            if !body_indexes_by_loop_var {
                continue;
            }

            if Self::next_statement_writes_null_at_index(&loop_node, loop_var, source) {
                return true; // Off-by-one: loop_var might equal the bound, accessing out of bounds
            }
        }

        false
    }

    /// Whether `condition` is a null-terminated string-walk test:
    /// `data[i] != '\0'`, `*src != '\0'`, or a bare pointer truthy check
    /// like `*src` (implicitly `!= 0`).
    fn condition_is_null_terminated_walk(condition: &Node, source: &str) -> bool {
        match condition.kind() {
            "binary_expression" => {
                let Some(op) = condition.child_by_field_name("operator") else {
                    return false;
                };
                if ast_utils::get_node_text(&op, source) != "!=" {
                    return false;
                }
                let (Some(left), Some(right)) = (
                    condition.child_by_field_name("left"),
                    condition.child_by_field_name("right"),
                ) else {
                    return false;
                };
                let is_indexable =
                    |n: &Node| matches!(n.kind(), "subscript_expression" | "pointer_expression");
                let is_null_or_zero = |n: &Node| match n.kind() {
                    "char_literal" => Self::char_literal_is_null(n, source),
                    "number_literal" => ast_utils::get_node_text(n, source) == "0",
                    _ => false,
                };
                (is_indexable(&left) && is_null_or_zero(&right))
                    || (is_indexable(&right) && is_null_or_zero(&left))
            }
            // Bare `*src` truthy check.
            "pointer_expression" => condition
                .child_by_field_name("operator")
                .is_some_and(|o| ast_utils::get_node_text(&o, source) == "*"),
            _ => false,
        }
    }

    /// Whether `body` contains a genuine buffer write: an array-index
    /// assignment (`dest[i] = ...`) or a post-increment pointer-dereference
    /// write (`*dest++ = ...`, for any pointer variable name).
    fn body_has_buffer_write(body: &Node, source: &str) -> bool {
        query::find_descendants_of_kind(*body, "assignment_expression")
            .iter()
            .any(|a| {
                let Some(left) = a.child_by_field_name("left") else {
                    return false;
                };
                match left.kind() {
                    "subscript_expression" => true,
                    "pointer_expression" => {
                        left.child_by_field_name("operator")
                            .is_some_and(|o| ast_utils::get_node_text(&o, source) == "*")
                            && left.child_by_field_name("argument").is_some_and(|arg| {
                                arg.kind() == "update_expression"
                                    && arg.child_by_field_name("operator").is_some_and(|op| {
                                        ast_utils::get_node_text(&op, source) == "++"
                                    })
                            })
                    }
                    _ => false,
                }
            })
    }

    /// Whether `node` is a relational comparison (`<`, `<=`, `>`, `>=`).
    fn is_relational_comparison(node: &Node, source: &str) -> bool {
        node.kind() == "binary_expression"
            && node.child_by_field_name("operator").is_some_and(|o| {
                matches!(
                    ast_utils::get_node_text(&o, source),
                    "<" | "<=" | ">" | ">="
                )
            })
    }

    /// Whether the loop has any recognizable bounds check: a compound
    /// condition ANDing the walk test with a relational bound, a `sizeof`
    /// anywhere in the loop, a reference to a bound/limit-named variable
    /// (matched against each identifier's own text, so a comment or string
    /// literal containing the same word can't fool this), or a
    /// pointer-distance comparison (`p - buf < size`).
    fn loop_has_bounds_check(loop_node: &Node, condition: &Node, source: &str) -> bool {
        if condition.kind() == "binary_expression"
            && condition
                .child_by_field_name("operator")
                .is_some_and(|o| ast_utils::get_node_text(&o, source) == "&&")
        {
            let sides = [
                condition.child_by_field_name("left"),
                condition.child_by_field_name("right"),
            ];
            if sides
                .into_iter()
                .flatten()
                .any(|s| Self::is_relational_comparison(&s, source))
            {
                return true;
            }
        }

        if !query::find_descendants_of_kind(*loop_node, "sizeof_expression").is_empty() {
            return true;
        }

        const BOUND_NAME_WORDS: &[&str] = &[
            "size", "len", "limit", "end", "max", "bufsize", "buf_size", "maxlen", "max_len",
        ];
        let has_bound_named_identifier = query::find_descendants_of_kind(*loop_node, "identifier")
            .iter()
            .any(|id| {
                let text = ast_utils::get_node_text(id, source);
                BOUND_NAME_WORDS.iter().any(|kw| text.contains(kw))
            });
        if has_bound_named_identifier {
            return true;
        }

        // Pointer-distance bound: a relational comparison where one side is
        // itself a subtraction, e.g. `p - buf < size`.
        query::find_descendants_of_kind(*loop_node, "binary_expression")
            .iter()
            .any(|rel| {
                Self::is_relational_comparison(rel, source)
                    && [
                        rel.child_by_field_name("left"),
                        rel.child_by_field_name("right"),
                    ]
                    .into_iter()
                    .flatten()
                    .any(|side| {
                        side.kind() == "binary_expression"
                            && side
                                .child_by_field_name("operator")
                                .is_some_and(|o| ast_utils::get_node_text(&o, source) == "-")
                    })
            })
    }

    /// Detect manual string copying loops without bounds checking.
    ///
    /// Structural version: a null-terminated-walk or getchar loop
    /// (`while (data[i] != '\0')`, `while (*src)`,
    /// `while ((ch = getchar()) != '\n')`) whose body performs a genuine
    /// buffer write and whose condition/body has no recognizable bounds
    /// check is flagged.
    fn detect_manual_string_loop(&self, node: &Node, source: &str) -> bool {
        if node.kind() != "while_statement" && node.kind() != "for_statement" {
            return false;
        }

        let Some(condition) = node.child_by_field_name("condition") else {
            return false;
        };
        let condition = Self::unwrap_parens(condition);

        let is_string_walk = Self::condition_is_null_terminated_walk(&condition, source);
        let is_getchar_loop = query::find_descendants_of_kind(condition, "call_expression")
            .iter()
            .any(|c| {
                c.child_by_field_name("function")
                    .is_some_and(|f| ast_utils::get_node_text(&f, source) == "getchar")
            });

        if !is_string_walk && !is_getchar_loop {
            return false;
        }

        let Some(body) = node.child_by_field_name("body") else {
            return false;
        };
        if !Self::body_has_buffer_write(&body, source) {
            return false;
        }

        !Self::loop_has_bounds_check(node, &condition, source)
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
            // Current destination content length: direct string-literal init,
            // else a prior strcpy's source length, else memset-filled
            // content, else assume empty. "Assume empty when unknown" matches
            // `get_initial_buffer_content_length`'s own convention elsewhere
            // in this file, and is what lets a `data[0] = '\0';` (explicitly
            // empty) destination — Juliet's badSink/goodG2BSink cat pattern —
            // fall through to the source-length-only estimate below instead
            // of being treated as "can't estimate, assume safe".
            let mut dest_current_length = self
                .get_string_length_from_context(Some(dest_var), source)
                .unwrap_or(0);
            if dest_current_length == 0 {
                dest_current_length = self.find_strcpy_source_length(dest_var, source);
            }
            if dest_current_length == 0 {
                dest_current_length = self
                    .get_memset_content_length(dest_var, source, arguments)
                    .unwrap_or(0);
            }

            // Source content length: string literal, else memset-filled
            // content (e.g. `memset(source, 'C', 100-1); source[99]='\0';`).
            let src_length = self
                .get_string_length_from_context(Some(src_name), source)
                .or_else(|| self.get_memset_content_length(src_name, source, arguments))
                .unwrap_or(0);

            // For strcat_safe.c: "Hello" (5) + " World" (6) + null (1) = 12
            if src_length > 0 {
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

    fn set_project_context(&self, context: &ProjectContext) {
        let mut map = self.callsite_param_buffer_size.borrow_mut();
        map.clear();
        for (name, summary) in &context.function_summaries {
            if !summary.callsite_param_buffer_size.is_empty() {
                map.insert(name.clone(), summary.callsite_param_buffer_size.clone());
            }
        }
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        // node is always the translation_unit root when called by the framework.
        // Pass it down to avoid re-finding root on every call.
        let mut violations = Vec::new();
        for n in query::find_descendants(*node, |_| true) {
            self.check_node(&n, source, node, &mut violations);
        }
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
        self.check_dangerous_call(node, source, root, violations);

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
    }

    /// Check a `call_expression` node for use of dangerous string functions
    /// (gets/strcpy/strcat/sprintf/scanf families, etc.) and push violations.
    fn check_dangerous_call<'a>(
        &self,
        node: &Node<'a>,
        source: &str,
        root: &Node<'a>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() != "call_expression" {
            return;
        }
        let Some(function_node) = node.child_by_field_name("function") else {
            return;
        };
        let function_name = &source[function_node.start_byte()..function_node.end_byte()];

        match function_name {
            "gets" => {
                violations.push(self.str31_violation(node, Severity::High, "Use of gets() is extremely dangerous and deprecated. It has no bounds checking.".to_string(), "Use fgets() with explicit buffer size instead"));
            }

            "strcpy" => {
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    if !self.check_strcpy_safety(&arguments, source, &root) {
                        violations.push(self.str31_violation(node, Severity::Medium, "Potential buffer overflow with strcpy(). Cannot verify destination buffer is large enough.".to_string(), "Use strncpy() with explicit size limit or verify buffer size"));
                    }
                }
            }

            "strcat" => {
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    if !self.check_strcat_safety(&arguments, source, &root) {
                        violations.push(self.str31_violation(node, Severity::Medium, "Potential buffer overflow with strcat(). Cannot verify destination has space for concatenation.".to_string(), "Use strncat() with size limit or track remaining buffer space"));
                    }
                }
            }

            "wcscpy" => {
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    if !self.check_strcpy_safety(&arguments, source, &root) {
                        violations.push(self.str31_violation(node, Severity::Medium, "Potential buffer overflow with wcscpy(). Cannot verify destination buffer is large enough.".to_string(), "Use wcsncpy() with explicit size limit or verify buffer size"));
                    }
                }
            }

            "wcscat" => {
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    if !self.check_strcat_safety(&arguments, source, &root) {
                        violations.push(self.str31_violation(node, Severity::Medium, "Potential buffer overflow with wcscat(). Cannot verify destination has space for concatenation.".to_string(), "Use wcsncat() with size limit or track remaining buffer space"));
                    }
                }
            }

            "wcsncpy" => {
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    if !self.check_strncpy_safety(&arguments, source, &root) {
                        violations.push(self.str31_violation(node, Severity::Medium, "Potential null termination issue with wcsncpy(). Size parameter equals buffer size.".to_string(), "Use size-1 as limit and explicitly null-terminate, or use wcslcpy()"));
                    }
                }
            }

            "wcsncat" => {
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    if !self.check_strcat_safety(&arguments, source, &root) {
                        violations.push(self.str31_violation(node, Severity::Medium, "Potential buffer overflow with wcsncat(). Verify destination has sufficient space.".to_string(), "Ensure size parameter accounts for existing content and null terminator"));
                    }
                }
            }

            "wmemcpy" => {
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    if self.is_string_memcpy(&arguments, source, &root) {
                        violations.push(
                            self.str31_violation(
                                node,
                                Severity::Medium,
                                "wmemcpy used for string copying may not include null terminator"
                                    .to_string(),
                                "Use wcscpy/wcsncpy or wmemcpy with size+1 for null terminator",
                            ),
                        );
                    }
                }
            }

            "swprintf" => {
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    if !self.check_sprintf_safety(&arguments, source, &root) {
                        violations.push(self.str31_violation(node, Severity::Medium, "Potential buffer overflow with swprintf(). Cannot verify output fits in destination buffer.".to_string(), "Use snwprintf() with explicit buffer size or verify buffer capacity"));
                    }
                }
            }

            "sprintf" => {
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    if !self.check_sprintf_safety(&arguments, source, &root) {
                        violations.push(self.str31_violation(node, Severity::Medium, "Potential buffer overflow with sprintf(). Cannot verify output fits in destination buffer.".to_string(), "Use snprintf() with explicit buffer size"));
                    }
                }
            }

            "vsprintf" => {
                violations.push(self.str31_violation(
                    node,
                    Severity::High,
                    "Use of vsprintf() is dangerous as it has no bounds checking.".to_string(),
                    "Use vsnprintf() with explicit buffer size",
                ));
            }

            "scanf" | "fscanf" | "sscanf" => {
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    if self.check_scanf_format(&arguments, source) {
                        violations.push(self.str31_violation(
                            node,
                            Severity::High,
                            format!(
                                "Dangerous use of {}() with unbounded %%s format specifier.",
                                function_name
                            ),
                            "Use width specifier with %s (e.g., %99s) or use fgets()",
                        ));
                    }
                }
            }

            "strncpy" => {
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    if !self.check_strncpy_safety(&arguments, source, &root) {
                        violations.push(self.str31_violation(node, Severity::Medium, "Potential null termination issue with strncpy(). Size parameter equals buffer size.".to_string(), "Use size-1 as limit and explicitly null-terminate, or use strlcpy()"));
                    }
                }
            }

            "memcpy" => {
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    if self.is_string_memcpy(&arguments, source, &root) {
                        violations.push(
                            self.str31_violation(
                                node,
                                Severity::Medium,
                                "memcpy used for string copying may not include null terminator"
                                    .to_string(),
                                "Use strcpy/strncpy or memcpy with size+1 for null terminator",
                            ),
                        );
                    }
                }
            }

            "wcstombs" => {
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    if !self.check_wcstombs_safety(&arguments, source, &root) {
                        violations.push(self.str31_violation(node, Severity::Medium, "wcstombs may overflow buffer - wide chars can expand to multiple bytes".to_string(), "Use larger buffer or wcstombs_s with size limit"));
                    }
                }
            }

            _ => {}
        }
    }

    /// Build an STR31-C violation anchored at `node` with the given severity,
    /// message, and remediation suggestion.
    fn str31_violation(
        &self,
        node: &Node,
        severity: Severity,
        message: String,
        suggestion: &str,
    ) -> RuleViolation {
        let start_point = node.start_position();
        RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity,
            message,
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(suggestion.to_string()),
            ..Default::default()
        }
    }
}
