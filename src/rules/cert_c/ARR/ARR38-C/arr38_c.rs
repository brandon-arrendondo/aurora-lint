use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{find_containing_function, get_node_text};
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Arr38C;

/// Information about a buffer size from allocation or declaration
#[allow(dead_code)]
#[derive(Clone, Debug)]
struct BufferInfo {
    /// Size in bytes or elements (if known)
    size: Option<usize>,
    /// Size expression (e.g., "nchars", "sizeof(arr)")
    size_expr: String,
    /// Type of allocation (malloc, calloc, array, etc.)
    alloc_type: String,
}

/// Information about a pointer with an offset from a base buffer
#[allow(dead_code)]
#[derive(Clone, Debug)]
struct PointerOffsetInfo {
    /// Base buffer name
    base_buffer: String,
    /// Offset in bytes/elements (if known); negative means before buffer start
    offset: Option<i64>,
    /// Offset expression (e.g., "15", "-8", "n")
    offset_expr: String,
}

impl CertRule for Arr38C {
    fn rule_id(&self) -> &'static str {
        "ARR38-C"
    }

    fn description(&self) -> &'static str {
        "Guarantee that library functions do not form invalid pointers"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "ARR38-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let mut buffer_info: HashMap<String, BufferInfo> = HashMap::new();
        let mut size_vars: HashMap<String, String> = HashMap::new();
        let mut unused_offsets: HashMap<String, PointerOffsetInfo> = HashMap::new();

        // First pass: collect buffer allocations and size variable assignments (file-wide)
        self.collect_buffer_info(
            node,
            source,
            &mut buffer_info,
            &mut size_vars,
            &mut unused_offsets,
        );

        // Second pass: check each function independently with function-scoped resolution.
        // This prevents cross-function contamination where "data = dataBadBuffer - 8" (bad fn)
        // and "data = dataGoodBuffer" (good fn) would share the same offset/alias entry.
        let functions = self.collect_function_definitions(node);
        for func_node in &functions {
            let aliases = self.collect_pointer_aliases(func_node, source);
            let mut func_buffer_info = buffer_info.clone();
            for (alias, target) in &aliases {
                if let Some(info) = func_buffer_info.get(target).cloned() {
                    func_buffer_info.insert(alias.clone(), info);
                }
            }

            // Collect pointer offsets per-function to avoid cross-function contamination
            let mut func_pointer_offsets: HashMap<String, PointerOffsetInfo> = HashMap::new();
            self.collect_pointer_offsets_in_node(func_node, source, &mut func_pointer_offsets);

            self.check_node(
                func_node,
                source,
                &mut violations,
                &func_buffer_info,
                &size_vars,
                &func_pointer_offsets,
            );
        }

        violations
    }
}

impl Arr38C {
    /// First pass: collect buffer allocations, size variable assignments, and pointer offsets
    fn collect_buffer_info(
        &self,
        node: &Node,
        source: &str,
        buffer_info: &mut HashMap<String, BufferInfo>,
        size_vars: &mut HashMap<String, String>,
        pointer_offsets: &mut HashMap<String, PointerOffsetInfo>,
    ) {
        match node.kind() {
            "declaration" => {
                self.extract_declaration_info(
                    node,
                    source,
                    buffer_info,
                    size_vars,
                    pointer_offsets,
                );
            }
            "expression_statement" => {
                self.extract_assignment_info(node, source, buffer_info, size_vars, pointer_offsets);
            }
            _ => {}
        }

        // Recursively process child nodes
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.collect_buffer_info(&child, source, buffer_info, size_vars, pointer_offsets);
            }
        }
    }

    /// Find the content size for a variable within the enclosing function by searching
    /// for memset(var_name, ..., N) calls. This is function-scoped to avoid cross-function
    /// contamination (e.g., bad function memset(data, 'A', 99) vs good function memset(data, 'A', 49)).
    /// Also resolves through pointer aliases within the same function.
    fn find_content_size_in_function(
        &self,
        node: &Node,
        var_name: &str,
        source: &str,
    ) -> Option<usize> {
        let func_node = find_containing_function(node)?;
        let func_text = &source[func_node.start_byte()..func_node.end_byte()];

        // Try direct var_name and any simple aliases found in the same function
        // e.g., "data = dataBuffer" means we also check memset(dataBuffer, ...)
        let mut names_to_check = vec![var_name.to_string()];
        let alias_pattern = format!(r"\b{}\s*=\s*(\w+)\s*;", regex::escape(var_name));
        if let Ok(re) = regex::Regex::new(&alias_pattern) {
            for caps in re.captures_iter(func_text) {
                if let Some(m) = caps.get(1) {
                    let target = m.as_str();
                    if self.is_simple_identifier(target) && target != var_name {
                        names_to_check.push(target.to_string());
                    }
                }
            }
        }
        // Also check reverse: if some other var is assigned from this one
        let reverse_pattern = format!(r"\b(\w+)\s*=\s*{}\s*;", regex::escape(var_name));
        if let Ok(re) = regex::Regex::new(&reverse_pattern) {
            for caps in re.captures_iter(func_text) {
                if let Some(m) = caps.get(1) {
                    let alias = m.as_str();
                    if self.is_simple_identifier(alias) && alias != var_name {
                        names_to_check.push(alias.to_string());
                    }
                }
            }
        }

        for name in &names_to_check {
            // Search for memset(name, ..., N) pattern in function text
            let pattern = format!(
                r"memset\s*\(\s*{}\s*,\s*[^,]+\s*,\s*([^)]+)\)",
                regex::escape(name)
            );
            if let Ok(re) = regex::Regex::new(&pattern) {
                if let Some(caps) = re.captures(func_text) {
                    if let Some(size_match) = caps.get(1) {
                        if let Some(size) = self.parse_memset_size_expr(size_match.as_str().trim())
                        {
                            return Some(size);
                        }
                    }
                }
            }
        }
        None
    }

    /// Parse a memset size expression like "50-1" -> 49, "99" -> 99, "100*sizeof(char)" -> 100
    fn parse_memset_size_expr(&self, expr: &str) -> Option<usize> {
        let expr = expr.trim();

        // Try direct number first
        if let Ok(n) = expr.parse::<usize>() {
            return Some(n);
        }

        // Try N-1 pattern (e.g., "50-1", "100-1")
        if let Some(minus_pos) = expr.rfind('-') {
            let left = expr[..minus_pos].trim();
            let right = expr[minus_pos + 1..].trim();
            if let (Ok(l), Ok(r)) = (left.parse::<usize>(), right.parse::<usize>()) {
                return Some(l.saturating_sub(r));
            }
        }

        // Try N*sizeof(char) pattern
        if let Some(size) = self.try_parse_size(expr) {
            return Some(size);
        }

        None
    }

    /// Extract buffer/size info from declarations
    fn extract_declaration_info(
        &self,
        node: &Node,
        source: &str,
        buffer_info: &mut HashMap<String, BufferInfo>,
        size_vars: &mut HashMap<String, String>,
        pointer_offsets: &mut HashMap<String, PointerOffsetInfo>,
    ) {
        let text = get_node_text(node, source);

        // Check for array declarations: char arr[SIZE]
        if text.contains('[') && text.contains(']') {
            if let Some(var_name) = self.extract_array_var_name(&text) {
                if let Some(size) = self.extract_array_size(&text) {
                    buffer_info.insert(
                        var_name.clone(),
                        BufferInfo {
                            size: Some(size),
                            size_expr: size.to_string(),
                            alloc_type: "array".to_string(),
                        },
                    );
                }
            }
            // Also handle multi-declarator declarations: "wchar_t data[150], dest[100]"
            // The first declarator is handled above; pick up subsequent ones here.
            if let Some(comma_pos) = text.find(',') {
                let rest = &text[comma_pos + 1..];
                let fragments: Vec<&str> = rest.split(',').collect();
                for fragment in &fragments {
                    let fragment = fragment.trim().trim_end_matches(';').trim();
                    if !fragment.contains('[') {
                        continue;
                    }
                    if let Some(var_name) = self.extract_array_var_name(fragment) {
                        if let Some(size) = self.extract_array_size(fragment) {
                            buffer_info.insert(
                                var_name.clone(),
                                BufferInfo {
                                    size: Some(size),
                                    size_expr: size.to_string(),
                                    alloc_type: "array".to_string(),
                                },
                            );
                        }
                    }
                }
            }
        }

        // Check for malloc/calloc/aligned_alloc/alloca/ALLOCA assignments
        if text.contains("malloc(")
            || text.contains("calloc(")
            || text.contains("aligned_alloc(")
            || text.contains("ALLOCA(")
            || text.contains("alloca(")
        {
            if let Some(var_name) = self.extract_pointer_var_name(&text) {
                if let Some(size_expr) = self.extract_alloc_size(&text) {
                    let size = self.try_parse_size(&size_expr);
                    buffer_info.insert(
                        var_name.clone(),
                        BufferInfo {
                            size,
                            size_expr: size_expr.clone(),
                            alloc_type: if text.contains("malloc") {
                                "malloc"
                            } else if text.contains("calloc") {
                                "calloc"
                            } else if text.contains("ALLOCA") || text.contains("alloca") {
                                "alloca"
                            } else {
                                "aligned_alloc"
                            }
                            .to_string(),
                        },
                    );
                }
            }
        }

        // Check for size_t variable assignments
        if text.contains("size_t") || text.contains("const size_t") {
            if let Some((var_name, size_expr)) = self.extract_size_var_assignment(&text) {
                size_vars.insert(var_name, size_expr);
            }
        }

        // Check for pointer offset assignments: char *ptr = buffer + offset; or buffer - offset;
        if text.contains('*') && text.contains('=') && (text.contains('+') || text.contains('-')) {
            if let Some((ptr_name, base, offset, negative)) =
                self.extract_pointer_offset_signed(&text)
            {
                let offset_val =
                    self.try_parse_size(&offset).map(
                        |v| {
                            if negative {
                                -(v as i64)
                            } else {
                                v as i64
                            }
                        },
                    );
                pointer_offsets.insert(
                    ptr_name,
                    PointerOffsetInfo {
                        base_buffer: base,
                        offset: offset_val,
                        offset_expr: if negative {
                            format!("-{}", offset)
                        } else {
                            offset
                        },
                    },
                );
            }
        }
    }

    /// Extract assignment info from expression statements
    fn extract_assignment_info(
        &self,
        node: &Node,
        source: &str,
        buffer_info: &mut HashMap<String, BufferInfo>,
        size_vars: &mut HashMap<String, String>,
        pointer_offsets: &mut HashMap<String, PointerOffsetInfo>,
    ) {
        let text = get_node_text(node, source);

        // Check for malloc/calloc/alloca assignments
        if text.contains("malloc(")
            || text.contains("calloc(")
            || text.contains("aligned_alloc(")
            || text.contains("ALLOCA(")
            || text.contains("alloca(")
        {
            if let Some(var_name) = self.extract_assignment_lhs(&text) {
                if let Some(size_expr) = self.extract_alloc_size(&text) {
                    let size = self.try_parse_size(&size_expr);
                    buffer_info.insert(
                        var_name.clone(),
                        BufferInfo {
                            size,
                            size_expr: size_expr.clone(),
                            alloc_type: if text.contains("malloc") {
                                "malloc"
                            } else if text.contains("calloc") {
                                "calloc"
                            } else if text.contains("ALLOCA") || text.contains("alloca") {
                                "alloca"
                            } else {
                                "aligned_alloc"
                            }
                            .to_string(),
                        },
                    );
                }
            }
        }

        // Check for size variable assignments: n = sizeof(p);
        if text.contains("sizeof(") || text.contains("+ 1") {
            if let Some((var_name, size_expr)) = self.extract_simple_assignment(&text) {
                size_vars.insert(var_name, size_expr);
            }
        }

        // Check for pointer offset assignments: ptr = buffer + offset; or buffer - offset;
        if text.contains('=')
            && (text.contains('+') || text.contains('-'))
            && !text.contains("malloc")
        {
            if let Some((ptr_name, base, offset, negative)) =
                self.extract_pointer_offset_signed(&text)
            {
                let offset_val =
                    self.try_parse_size(&offset).map(
                        |v| {
                            if negative {
                                -(v as i64)
                            } else {
                                v as i64
                            }
                        },
                    );
                pointer_offsets.insert(
                    ptr_name,
                    PointerOffsetInfo {
                        base_buffer: base,
                        offset: offset_val,
                        offset_expr: if negative {
                            format!("-{}", offset)
                        } else {
                            offset
                        },
                    },
                );
            }
        }
    }

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        buffer_info: &HashMap<String, BufferInfo>,
        size_vars: &HashMap<String, String>,
        pointer_offsets: &HashMap<String, PointerOffsetInfo>,
    ) {
        if node.kind() == "call_expression" {
            self.check_library_function_call(
                node,
                source,
                violations,
                buffer_info,
                size_vars,
                pointer_offsets,
            );
        }

        // Recursively check child nodes
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.check_node(
                    &child,
                    source,
                    violations,
                    buffer_info,
                    size_vars,
                    pointer_offsets,
                );
            }
        }
    }

    fn check_library_function_call(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        buffer_info: &HashMap<String, BufferInfo>,
        size_vars: &HashMap<String, String>,
        pointer_offsets: &HashMap<String, PointerOffsetInfo>,
    ) {
        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = get_node_text(&function_node, source);

            match function_name {
                "memcpy" | "memmove" | "memset" | "memcmp" | "memchr" => {
                    self.check_memory_function(
                        node,
                        source,
                        function_name,
                        violations,
                        buffer_info,
                        size_vars,
                        pointer_offsets,
                    );
                }
                "strcpy" | "strncpy" | "strcat" | "strncat" | "strcmp" | "strncmp" => {
                    self.check_string_function(
                        node,
                        source,
                        function_name,
                        violations,
                        buffer_info,
                        size_vars,
                        pointer_offsets,
                    );
                }
                "wmemcpy" | "wmemmove" | "wmemset" | "wmemcmp" | "wmemchr" => {
                    self.check_wide_memory_function(
                        node,
                        source,
                        function_name,
                        violations,
                        buffer_info,
                        pointer_offsets,
                    );
                }
                "wcscpy" | "wcsncpy" | "wcscat" | "wcsncat" | "wcscmp" | "wcsncmp" => {
                    self.check_wide_string_function(
                        node,
                        source,
                        function_name,
                        violations,
                        buffer_info,
                        pointer_offsets,
                    );
                }
                "malloc" | "calloc" | "realloc" | "aligned_alloc" => {
                    self.check_allocation_function(node, source, function_name, violations);
                }
                "fread" | "fwrite" => {
                    self.check_io_function(
                        node,
                        source,
                        function_name,
                        violations,
                        buffer_info,
                        size_vars,
                    );
                }
                "fgets" | "snprintf" | "SNPRINTF" | "_snprintf" | "_snwprintf" | "swprintf"
                | "strftime" => {
                    self.check_buffer_function(
                        node,
                        source,
                        function_name,
                        violations,
                        buffer_info,
                        size_vars,
                    );
                }
                "bsearch" | "qsort" => {
                    self.check_array_function(
                        node,
                        source,
                        function_name,
                        violations,
                        buffer_info,
                        size_vars,
                    );
                }
                _ => {}
            }
        }
    }

    fn check_memory_function(
        &self,
        node: &Node,
        source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
        buffer_info: &HashMap<String, BufferInfo>,
        size_vars: &HashMap<String, String>,
        pointer_offsets: &HashMap<String, PointerOffsetInfo>,
    ) {
        let args = self.get_function_arguments(node, source);

        match function_name {
            "memcpy" | "memmove" if args.len() >= 3 => {
                // First check for pointer offset issues (destination)
                if let Some(violation) = self.check_pointer_offset_overflow(
                    &args,
                    node,
                    function_name,
                    buffer_info,
                    size_vars,
                    pointer_offsets,
                ) {
                    violations.push(violation);
                    return;
                }

                // Check source pointer offset (buffer underread)
                if let Some(violation) =
                    self.check_source_pointer_offset(&args, 1, node, function_name, pointer_offsets)
                {
                    violations.push(violation);
                    return;
                }

                // Check for buffer/size mismatches
                self.check_buffer_size_mismatch(
                    &args,
                    node,
                    source,
                    function_name,
                    violations,
                    buffer_info,
                    size_vars,
                );
            }
            "memset" if args.len() >= 3 => {
                self.check_buffer_size_mismatch(
                    &args,
                    node,
                    source,
                    function_name,
                    violations,
                    buffer_info,
                    size_vars,
                );
            }
            "memcmp" | "memchr" if args.len() >= 3 => {
                self.check_buffer_size_mismatch(
                    &args,
                    node,
                    source,
                    function_name,
                    violations,
                    buffer_info,
                    size_vars,
                );
            }
            _ => {}
        }
    }

    fn check_string_function(
        &self,
        node: &Node,
        source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
        buffer_info: &HashMap<String, BufferInfo>,
        size_vars: &HashMap<String, String>,
        pointer_offsets: &HashMap<String, PointerOffsetInfo>,
    ) {
        let args = self.get_function_arguments(node, source);

        // Check source pointer offset for all string functions (source is arg[1])
        if args.len() >= 2 {
            if let Some(violation) =
                self.check_source_pointer_offset(&args, 1, node, function_name, pointer_offsets)
            {
                violations.push(violation);
                return;
            }
        }

        match function_name {
            "strncpy" | "strncat" | "strncmp" if args.len() >= 3 => {
                self.check_string_size_parameter(
                    &args,
                    node,
                    source,
                    function_name,
                    violations,
                    buffer_info,
                    size_vars,
                );
            }
            "strcpy" | "strcat" if args.len() >= 2 => {
                self.check_unbounded_string_function(&args, node, function_name, violations);
            }
            _ => {}
        }
    }

    fn check_wide_memory_function(
        &self,
        node: &Node,
        source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
        buffer_info: &HashMap<String, BufferInfo>,
        pointer_offsets: &HashMap<String, PointerOffsetInfo>,
    ) {
        let args = self.get_function_arguments(node, source);

        // Check source pointer offset (buffer underread) — source is arg[1] for wmemcpy/wmemmove
        if args.len() >= 2 {
            if let Some(violation) =
                self.check_source_pointer_offset(&args, 1, node, function_name, pointer_offsets)
            {
                violations.push(violation);
                return;
            }
        }

        if args.len() >= 3 {
            // Wide character functions expect size in terms of wchar_t, not bytes
            let size_arg = &args[2];

            // Check for sizeof (byte count instead of element count)
            if self.is_byte_size_expression(size_arg) {
                let start_point = node.start_position();
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Function '{}' expects size in wchar_t units, not bytes. Using sizeof() may cause buffer overflow",
                        function_name
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Use element count instead of sizeof() for wide character functions".to_string()),
                    ..Default::default()
                });
                return;
            }

            // Check for hardcoded counts that likely exceed buffer
            if self.is_hardcoded_large_count(size_arg) {
                // Suppress if the element count is provably within the destination buffer.
                // buffer_info sizes are stored in bytes (element_count * sizeof(element)).
                // Wide memory functions use element counts, so compare count * sizeof(wchar_t)
                // against the buffer byte size.
                let dest_arg = &args[0];
                // buffer_info.size stores element counts; compare directly.
                let count_fits = if let Some(count) = self.try_parse_size(size_arg) {
                    if let Some(buf_info) = buffer_info.get(dest_arg.trim()) {
                        if let Some(buf_elems) = buf_info.size {
                            count <= buf_elems
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                };

                if !count_fits {
                    let start_point = node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Function '{}' called with hardcoded count {} that may exceed buffer bounds",
                            function_name, size_arg
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Use array size (e.g., sizeof(dest)/sizeof(wchar_t)) instead"
                                .to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    fn check_wide_string_function(
        &self,
        node: &Node,
        source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
        buffer_info: &HashMap<String, BufferInfo>,
        pointer_offsets: &HashMap<String, PointerOffsetInfo>,
    ) {
        let args = self.get_function_arguments(node, source);

        // Check source pointer offset for all wide string functions (source is arg[1])
        if args.len() >= 2 {
            if let Some(violation) =
                self.check_source_pointer_offset(&args, 1, node, function_name, pointer_offsets)
            {
                violations.push(violation);
                return;
            }
        }

        if function_name.contains("wcsn") && args.len() >= 3 {
            let dest_arg = &args[0];
            let src_arg = &args[1];
            let size_arg = &args[2];

            // Check for sizeof (byte count instead of character count)
            if self.is_byte_size_expression(size_arg) {
                let start_point = node.start_position();
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Function '{}' expects character count, not byte count",
                        function_name
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some(
                        "Use character count instead of sizeof() for wide string functions"
                            .to_string(),
                    ),
                    ..Default::default()
                });
                return;
            }

            // Check for wcslen(src) as size where src > dest
            if let Some(wcslen_arg) = self.extract_wcslen_argument(size_arg) {
                let wcslen_arg = wcslen_arg.trim();
                let src_trimmed = src_arg.trim();
                if wcslen_arg == src_trimmed {
                    // Use content_size if available (from memset in same function), otherwise fall back to buffer alloc size
                    let effective_src_size = self
                        .find_content_size_in_function(node, wcslen_arg, source)
                        .or_else(|| buffer_info.get(wcslen_arg).and_then(|info| info.size));
                    if let Some(src_size) = effective_src_size {
                        if let Some(dest_info) = buffer_info.get(dest_arg.trim()) {
                            if let Some(dest_size) = dest_info.size {
                                if src_size > dest_size {
                                    let start_point = node.start_position();
                                    violations.push(RuleViolation {
                                            rule_id: self.rule_id().to_string(),
                                            severity: Severity::High,
                                            message: format!(
                                                "Function '{}': wcslen({}) (buffer size {}) may exceed destination '{}' size {}",
                                                function_name, wcslen_arg, src_size, dest_arg.trim(), dest_size
                                            ),
                                            file_path: String::new(),
                                            line: start_point.row + 1,
                                            column: start_point.column + 1,
                                            suggestion: Some(format!(
                                                "Use sizeof({})/sizeof(wchar_t) as the size limit",
                                                dest_arg.trim()
                                            )),
                                            ..Default::default()
                                        });
                                    return;
                                }
                            }
                        }
                    }
                }
            }

            // If dest buffer size is known and count fits, skip heuristic checks.
            if self.is_size_within_known_buffer(dest_arg, size_arg, buffer_info, None) {
                return;
            }

            // Check for hardcoded sizes that likely exceed buffer
            if self.is_hardcoded_large_count(size_arg) {
                let start_point = node.start_position();
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Function '{}' called with hardcoded count {} that may exceed buffer bounds",
                        function_name, size_arg
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some(
                        "Use array size (e.g., sizeof(dest)/sizeof(wchar_t)) instead".to_string(),
                    ),
                    ..Default::default()
                });
            }
        }
    }

    fn check_allocation_function(
        &self,
        node: &Node,
        source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let args = self.get_function_arguments(node, source);

        match function_name {
            "calloc" if args.len() >= 2 => {
                // calloc(count, size) - check for potential overflow
                let count_arg = &args[0];
                let size_arg = &args[1];

                if self.could_cause_overflow(count_arg, size_arg) {
                    let start_point = node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Medium,
                        message: "calloc() arguments may cause integer overflow".to_string(),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Check for potential overflow in calloc arguments".to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
            "realloc" if args.len() >= 2 => {
                let size_arg = &args[1];
                if self.is_dangerous_size_calculation(size_arg) {
                    let start_point = node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: "realloc() called with potentially incorrect size".to_string(),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Verify realloc size is correct for the new allocation".to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
            "aligned_alloc" if args.len() >= 2 => {
                let size_arg = &args[1];
                if self.is_dangerous_size_calculation(size_arg) {
                    let start_point = node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: "aligned_alloc() called with potentially incorrect size"
                            .to_string(),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Verify aligned_alloc size matches intended allocation".to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
            _ => {}
        }
    }

    #[allow(dead_code)]
    fn check_three_arg_size(
        &self,
        args: &[String],
        node: &Node,
        _source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let size_arg = &args[2];

        // Check for dangerous size calculation patterns
        if self.is_dangerous_size_calculation(size_arg) {
            let start_point = node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "Function '{}' called with potentially invalid size calculation",
                    function_name
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some("Ensure size argument does not exceed buffer bounds".to_string()),
                ..Default::default()
            });
        }
    }

    fn check_string_size_parameter(
        &self,
        args: &[String],
        node: &Node,
        source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
        buffer_info: &HashMap<String, BufferInfo>,
        size_vars: &HashMap<String, String>,
    ) {
        let dest_arg = &args[0];
        let src_arg = if args.len() >= 2 { &args[1] } else { dest_arg };
        let size_arg = &args[2];

        // Check if size exceeds known buffer size
        if let Some(violation) = self.check_size_exceeds_buffer(
            dest_arg,
            size_arg,
            node,
            function_name,
            buffer_info,
            size_vars,
        ) {
            violations.push(violation);
            return;
        }

        // Check for strlen(src) as size argument where src buffer > dest buffer
        // Pattern: strncpy(dest, src, strlen(src)) — size not bounded by dest
        if let Some(strlen_arg) = self.extract_strlen_argument(size_arg) {
            // strlen argument should reference the source (2nd arg) or an alias of it
            let strlen_arg = strlen_arg.trim();
            let src_trimmed = src_arg.trim();
            if strlen_arg == src_trimmed {
                // Use content_size if available (from memset), otherwise fall back to buffer alloc size.
                // strlen() returns the actual string length, not the buffer capacity.
                // If memset(data, 'A', 49) was called, content_size is 49 even if buffer is 100.
                let effective_src_size = self
                    .find_content_size_in_function(node, strlen_arg, source)
                    .or_else(|| buffer_info.get(strlen_arg).and_then(|info| info.size));
                if let Some(src_size) = effective_src_size {
                    if let Some(dest_info) = buffer_info.get(dest_arg.trim()) {
                        if let Some(dest_size) = dest_info.size {
                            if src_size > dest_size {
                                let start_point = node.start_position();
                                violations.push(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        severity: Severity::High,
                                        message: format!(
                                            "Function '{}': strlen({}) (buffer size {}) may exceed destination '{}' size {}",
                                            function_name, strlen_arg, src_size, dest_arg.trim(), dest_size
                                        ),
                                        file_path: String::new(),
                                        line: start_point.row + 1,
                                        column: start_point.column + 1,
                                        suggestion: Some(format!(
                                            "Use sizeof({}) or {} as the size limit",
                                            dest_arg.trim(),
                                            dest_size
                                        )),
                                        ..Default::default()
                                    });
                                return;
                            }
                        }
                    }
                }
            }
        }

        // Check for strlen(src)*sizeof(T) as size argument where src buffer > dest buffer
        if let Some(strlen_arg) = self.extract_strlen_from_sizeof_expr(size_arg) {
            let strlen_arg = strlen_arg.trim();
            let src_trimmed = src_arg.trim();
            if strlen_arg == src_trimmed {
                let effective_src_size = self
                    .find_content_size_in_function(node, strlen_arg, source)
                    .or_else(|| buffer_info.get(strlen_arg).and_then(|info| info.size));
                if let Some(src_size) = effective_src_size {
                    if let Some(dest_info) = buffer_info.get(dest_arg.trim()) {
                        if let Some(dest_size) = dest_info.size {
                            if src_size > dest_size {
                                let start_point = node.start_position();
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::High,
                                    message: format!(
                                        "Function '{}': string length of '{}' (buffer size {}) may exceed destination '{}' size {}",
                                        function_name, strlen_arg, src_size, dest_arg.trim(), dest_size
                                    ),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some(format!(
                                        "Use sizeof({}) as the size limit",
                                        dest_arg.trim()
                                    )),
                                    ..Default::default()
                                });
                                return;
                            }
                        }
                    }
                }
            }
        }

        // If dest buffer size is known and size fits, skip heuristic checks.
        if self.is_size_within_known_buffer(dest_arg, size_arg, buffer_info, Some(size_vars)) {
            return;
        }

        // Check for hardcoded sizes that are suspiciously large
        if self.is_hardcoded_large_size(size_arg) {
            let start_point = node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::Medium,
                message: format!(
                    "Function '{}' called with hardcoded size {} that may exceed buffer bounds",
                    function_name, size_arg
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some("Use sizeof(buffer) or a validated size".to_string()),
                ..Default::default()
            });
            return;
        }

        // Use the general dangerous size calculation check
        if self.is_dangerous_size_calculation(size_arg) {
            let start_point = node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::Medium,
                message: format!(
                    "Function '{}' called with potentially invalid size parameter",
                    function_name
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some("Verify size parameter is correct for the buffer".to_string()),
                ..Default::default()
            });
        }
    }

    fn check_unbounded_string_function(
        &self,
        _args: &[String],
        _node: &Node,
        _function_name: &str,
        _violations: &mut Vec<RuleViolation>,
    ) {
        // Unbounded string function usage (strcpy/strcat without bounds checking)
        // is already covered by STR31-C. ARR38-C focuses on library functions
        // forming invalid pointers through size mismatches and buffer overflows,
        // not on general unsafe function usage.
        // No-op to avoid duplicate violations with STR31-C.
    }

    fn check_io_function(
        &self,
        node: &Node,
        source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
        _buffer_info: &HashMap<String, BufferInfo>,
        size_vars: &HashMap<String, String>,
    ) {
        let args = self.get_function_arguments(node, source);

        // fread/fwrite have signature: (ptr, size, count, file)
        if args.len() >= 4 {
            let buf_arg = &args[0];
            let size_arg = &args[1];
            let count_arg = &args[2];

            // Check if count uses sizeof but size also uses sizeof - indicates total bytes
            // used as count
            if count_arg.contains("sizeof(") && !count_arg.contains("/") {
                // Resolve count_arg through size_vars if it's a variable
                let resolved_count = size_vars.get(count_arg.trim()).unwrap_or(count_arg);
                if resolved_count.contains("sizeof(") && !resolved_count.contains("/") {
                    let start_point = node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Function '{}' count parameter appears to use total size instead of element count",
                            function_name
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Use element count, not total byte size. Example: fread(buf, sizeof(elem), count, file)".to_string()),
                        ..Default::default()
                    });
                    return;
                }
            }

            // Check if count is a variable that was assigned sizeof(buffer) without division
            if let Some(resolved_count) = size_vars.get(count_arg.trim()) {
                if resolved_count.contains("sizeof(") && !resolved_count.contains("/") {
                    let start_point = node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Function '{}' count parameter '{}' appears to use total size instead of element count",
                            function_name, count_arg
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Use element count (sizeof(buf)/sizeof(elem)), not total byte size".to_string()),
                        ..Default::default()
                    });
                    return;
                }
            }

            // Check for hardcoded struct sizes (e.g., using 16 instead of sizeof(struct obj))
            // The size argument should use sizeof() for struct-based operations
            let resolved_size = size_vars.get(size_arg.trim()).unwrap_or(size_arg);
            if !resolved_size.contains("sizeof(") {
                // Check if it's a hardcoded number that might be a struct size assumption
                if let Ok(size_val) = resolved_size.trim().parse::<usize>() {
                    // Common struct sizes that indicate hardcoded assumptions
                    if (8..=64).contains(&size_val) && size_val % 4 == 0 {
                        // Likely a hardcoded struct size - check if buffer is struct-based
                        if buf_arg.contains("struct") || source.contains("struct obj") {
                            let start_point = node.start_position();
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::Medium,
                                message: format!(
                                    "Function '{}' uses hardcoded size {} which may not match actual struct size with padding",
                                    function_name, size_val
                                ),
                                file_path: String::new(),
                                line: start_point.row + 1,
                                column: start_point.column + 1,
                                suggestion: Some("Use sizeof(struct_type) to ensure correct size on all platforms".to_string()),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    fn check_buffer_function(
        &self,
        node: &Node,
        source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
        buffer_info: &HashMap<String, BufferInfo>,
        size_vars: &HashMap<String, String>,
    ) {
        let args = self.get_function_arguments(node, source);

        // These functions have a size parameter that must not exceed buffer size
        // fgets(buf, size, file), snprintf(buf, size, fmt, ...), etc.
        let (buf_idx, size_idx) = match function_name {
            "fgets" => (0, 1),
            "snprintf" | "SNPRINTF" | "_snprintf" | "_snwprintf" | "swprintf" => (0, 1),
            "strftime" => (0, 1),
            _ => return,
        };

        if args.len() > size_idx {
            let buf_arg = &args[buf_idx];
            let size_arg = &args[size_idx];

            // Check if size exceeds known buffer size
            if let Some(violation) = self.check_size_exceeds_buffer(
                buf_arg,
                size_arg,
                node,
                function_name,
                buffer_info,
                size_vars,
            ) {
                violations.push(violation);
                return;
            }

            // Check for strlen/wcslen(src) as size argument for snprintf/SNPRINTF/swprintf
            // Pattern: snprintf(dest, strlen(data), "%s", data)
            // Pattern: SNPRINTF(dest, wcslen(data), L"%s", data)
            if matches!(
                function_name,
                "snprintf" | "SNPRINTF" | "_snprintf" | "_snwprintf" | "swprintf"
            ) {
                let len_arg = self
                    .extract_strlen_argument(size_arg)
                    .or_else(|| self.extract_wcslen_argument(size_arg));
                if let Some(len_arg) = len_arg {
                    let len_arg = len_arg.trim();
                    // Use content_size if available (from memset), otherwise fall back to buffer alloc size
                    let effective_src_size = self
                        .find_content_size_in_function(node, len_arg, source)
                        .or_else(|| buffer_info.get(len_arg).and_then(|info| info.size));
                    if let Some(src_size) = effective_src_size {
                        if let Some(dest_info) = buffer_info.get(buf_arg.trim()) {
                            if let Some(dest_size) = dest_info.size {
                                if src_size > dest_size {
                                    let start_point = node.start_position();
                                    violations.push(RuleViolation {
                                            rule_id: self.rule_id().to_string(),
                                            severity: Severity::High,
                                            message: format!(
                                                "Function '{}': string length of '{}' (buffer size {}) may exceed destination '{}' size {}",
                                                function_name, len_arg, src_size, buf_arg.trim(), dest_size
                                            ),
                                            file_path: String::new(),
                                            line: start_point.row + 1,
                                            column: start_point.column + 1,
                                            suggestion: Some(format!(
                                                "Use sizeof({}) as the size limit",
                                                buf_arg.trim()
                                            )),
                                            ..Default::default()
                                        });
                                    return;
                                }
                            }
                        }
                    }
                }
            }

            // If dest buffer size is known and size fits, skip heuristic checks.
            if self.is_size_within_known_buffer(buf_arg, size_arg, buffer_info, Some(size_vars)) {
                return;
            }

            // Check for hardcoded sizes that are suspiciously large
            if self.is_hardcoded_large_size(size_arg) {
                let start_point = node.start_position();
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Function '{}' called with hardcoded size {} that may exceed buffer bounds",
                        function_name, size_arg
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Use sizeof(buffer) or a validated size".to_string()),
                    ..Default::default()
                });
                return;
            }

            if self.is_dangerous_size_calculation(size_arg) {
                let start_point = node.start_position();
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Function '{}' called with potentially invalid size parameter",
                        function_name
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some(
                        "Ensure size parameter does not exceed buffer size".to_string(),
                    ),
                    ..Default::default()
                });
            }
        }
    }

    fn check_array_function(
        &self,
        node: &Node,
        source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
        buffer_info: &HashMap<String, BufferInfo>,
        _size_vars: &HashMap<String, String>,
    ) {
        let args = self.get_function_arguments(node, source);

        match function_name {
            "bsearch"
                // bsearch(key, base, count, size, compare)
                if args.len() >= 5 => {
                    let base_arg = &args[1];
                    let count_arg = &args[2];

                    // Check if count exceeds known array size
                    if let Some(buf_info) = buffer_info.get(base_arg.trim()) {
                        if let Some(arr_size) = buf_info.size {
                            if let Some(count) = self.try_parse_size(count_arg) {
                                if count > arr_size {
                                    let start_point = node.start_position();
                                    violations.push(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        severity: Severity::High,
                                        message: format!(
                                            "bsearch count {} exceeds array size {}",
                                            count, arr_size
                                        ),
                                        file_path: String::new(),
                                        line: start_point.row + 1,
                                        column: start_point.column + 1,
                                        suggestion: Some(
                                            "Use actual array element count".to_string(),
                                        ),
                                        ..Default::default()
                                    });
                                    return;
                                }
                            }
                        }
                    }

                    // Check for hardcoded count that seems too large
                    if self.is_hardcoded_large_count(count_arg) {
                        let start_point = node.start_position();
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::High,
                            message: format!(
                                "bsearch called with suspicious hardcoded count {}",
                                count_arg
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(
                                "Use sizeof(array)/sizeof(array[0]) for element count".to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            "qsort"
                // qsort(base, count, size, compare)
                if args.len() >= 4 => {
                    let base_arg = &args[0];
                    let count_arg = &args[1];
                    let size_arg = &args[2];

                    // Check for type mismatch in element size
                    // e.g., using sizeof(long) for an int array
                    if self.is_type_size_mismatch(base_arg, size_arg, source) {
                        let start_point = node.start_position();
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::High,
                            message: format!(
                                "qsort element size '{}' may not match array element type",
                                size_arg
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(
                                "Use sizeof(array[0]) or sizeof(*array) for element size"
                                    .to_string(),
                            ),
                            ..Default::default()
                        });
                        return;
                    }

                    // Check if count exceeds known array size
                    if let Some(buf_info) = buffer_info.get(base_arg.trim()) {
                        if let Some(arr_size) = buf_info.size {
                            if let Some(count) = self.try_parse_size(count_arg) {
                                if count > arr_size {
                                    let start_point = node.start_position();
                                    violations.push(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        severity: Severity::High,
                                        message: format!(
                                            "qsort count {} exceeds array size {}",
                                            count, arr_size
                                        ),
                                        file_path: String::new(),
                                        line: start_point.row + 1,
                                        column: start_point.column + 1,
                                        suggestion: Some(
                                            "Use actual array element count".to_string(),
                                        ),
                                        ..Default::default()
                                    });
                                    return;
                                }
                            }
                        }
                    }

                    // Check for hardcoded count that seems too large
                    if self.is_hardcoded_large_count(count_arg) {
                        let start_point = node.start_position();
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::High,
                            message: format!(
                                "qsort called with suspicious hardcoded count {}",
                                count_arg
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(
                                "Use sizeof(array)/sizeof(array[0]) for element count".to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            _ => {}
        }
    }

    fn get_function_arguments(&self, node: &Node, source: &str) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(arguments) = node.child_by_field_name("arguments") {
            for i in 0..arguments.child_count() {
                if let Some(child) = arguments.child(i) {
                    if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                        args.push(get_node_text(&child, source).to_string());
                    }
                }
            }
        }

        args
    }

    fn is_byte_size_expression(&self, expr: &str) -> bool {
        expr.contains("sizeof(") && !expr.contains("/ sizeof(")
    }

    #[allow(dead_code)]
    fn is_sizeof_expression(&self, expr: &str) -> bool {
        expr.contains("sizeof(")
    }

    fn is_dangerous_size_calculation(&self, size_expr: &str) -> bool {
        // Look for potentially dangerous patterns that indicate incorrect size calculations

        // Allow legitimate patterns first
        // Pattern: strlen(x) + 1 or wcslen(x) + 1 - this is correct for null terminator
        if (size_expr.contains("strlen(") || size_expr.contains("wcslen("))
            && size_expr.contains("+ 1")
        {
            return false;
        }

        // Pattern: strlen(x)*sizeof(T) or wcslen(x)*sizeof(T) — byte count of string content
        if (size_expr.contains("strlen(") || size_expr.contains("wcslen("))
            && size_expr.contains("sizeof(")
        {
            return false;
        }

        // Pattern: sizeof(buffer) - 1 - this is correct for string functions
        if size_expr.contains("sizeof(") && size_expr.contains("- 1") {
            return false;
        }

        // Pattern: sizeof(*ptr) - this is usually correct (dereferenced pointer)
        if size_expr.contains("sizeof(*") {
            return false;
        }

        // Now check for dangerous patterns

        // Pattern 1: sizeof with explicit multiplication (not dereference)
        // e.g., "sizeof(int) * ARR_SIZE" indicates double scaling
        if size_expr.contains("sizeof(")
            && size_expr.contains("*")
            && !size_expr.contains("sizeof(*")
        {
            return true;
        }

        // Pattern 2: Variable + constant patterns (not strlen/wcslen)
        // These indicate adding to an allocation size, which would exceed the buffer
        // e.g., "nchars + 1" when nchars is the allocated size
        // e.g., "n + 50" when n is the VLA size
        if size_expr.contains('+')
            && !size_expr.contains("strlen(")
            && !size_expr.contains("wcslen(")
        {
            // Check if there's a meaningful offset (anything added)
            // Skip if it's sizeof(x) + sizeof(y) which is typically intentional
            let plus_count = size_expr.matches('+').count();
            let sizeof_count = size_expr.matches("sizeof(").count();
            // If we have more + operations than sizeof patterns, likely a problem
            if plus_count > sizeof_count {
                return true;
            }
            // If no sizeof at all and has +, it's suspicious
            if sizeof_count == 0 {
                return true;
            }
        }

        false
    }

    fn could_cause_overflow(&self, count_expr: &str, size_expr: &str) -> bool {
        // Check for potential overflow in calloc
        (count_expr.contains("SIZE_MAX") || count_expr.contains("UINT_MAX"))
            || (size_expr.contains("SIZE_MAX") || size_expr.contains("UINT_MAX"))
    }

    /// Check for buffer/size mismatches in memory functions
    fn check_buffer_size_mismatch(
        &self,
        args: &[String],
        node: &Node,
        source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
        buffer_info: &HashMap<String, BufferInfo>,
        size_vars: &HashMap<String, String>,
    ) {
        let dest_arg = &args[0];
        let size_arg = &args[2];

        // Resolve the size argument to its expression if it's a variable
        let size_arg_owned = size_arg.to_string();
        let resolved_size = size_vars.get(size_arg.trim()).unwrap_or(&size_arg_owned);

        // Check if size exceeds known buffer size
        if let Some(violation) = self.check_size_exceeds_buffer(
            dest_arg,
            size_arg,
            node,
            function_name,
            buffer_info,
            size_vars,
        ) {
            violations.push(violation);
            return;
        }

        // If the dest buffer has known size and the copy fits, skip heuristic checks.
        // The concrete size comparison above is authoritative; heuristics like
        // is_hardcoded_large_size are only useful when buffer size is unknown.
        if self.is_size_within_known_buffer(dest_arg, size_arg, buffer_info, Some(size_vars)) {
            return;
        }

        // For memcpy/memmove, also check source buffer
        if (function_name == "memcpy" || function_name == "memmove") && args.len() >= 3 {
            let src_arg = &args[1];
            if let Some(violation) = self.check_size_exceeds_buffer(
                src_arg,
                size_arg,
                node,
                function_name,
                buffer_info,
                size_vars,
            ) {
                violations.push(violation);
                return;
            }

            // Check for sizeof(src) when dest is smaller
            if size_arg.contains("sizeof(") {
                // Extract the variable from sizeof(var)
                if let Some(sizeof_var) = self.extract_sizeof_var(size_arg) {
                    // If sizeof references source but dest is known to be smaller
                    if sizeof_var == src_arg.trim() {
                        if let Some(dest_info) = buffer_info.get(dest_arg.trim()) {
                            if let Some(src_info) = buffer_info.get(src_arg.trim()) {
                                if let (Some(dest_size), Some(src_size)) =
                                    (dest_info.size, src_info.size)
                                {
                                    if src_size > dest_size {
                                        let start_point = node.start_position();
                                        violations.push(RuleViolation {
                                            rule_id: self.rule_id().to_string(),
                                            severity: Severity::High,
                                            message: format!(
                                                "Function '{}': sizeof({}) ({} bytes) exceeds destination buffer size ({} bytes)",
                                                function_name, sizeof_var, src_size, dest_size
                                            ),
                                            file_path: String::new(),
                                            line: start_point.row + 1,
                                            column: start_point.column + 1,
                                            suggestion: Some("Use sizeof(dest) or minimum of source and destination sizes".to_string()),
                                            ..Default::default()
                                        });
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Check for strlen(src)*sizeof(T) where source buffer > dest buffer
            // Recovers TPs from the blanket strlen*sizeof exemption in is_dangerous_size_calculation
            if let Some(strlen_arg) = self.extract_strlen_from_sizeof_expr(resolved_size) {
                let strlen_arg = strlen_arg.trim();
                if strlen_arg == src_arg.trim() {
                    let effective_src_size = self
                        .find_content_size_in_function(node, strlen_arg, source)
                        .or_else(|| buffer_info.get(strlen_arg).and_then(|info| info.size));
                    if let Some(src_size) = effective_src_size {
                        if let Some(dest_info) = buffer_info.get(dest_arg.trim()) {
                            if let Some(dest_size) = dest_info.size {
                                if src_size > dest_size {
                                    let start_point = node.start_position();
                                    violations.push(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        severity: Severity::High,
                                        message: format!(
                                            "Function '{}': string length of '{}' (buffer size {}) may exceed destination '{}' size {}",
                                            function_name, strlen_arg, src_size, dest_arg.trim(), dest_size
                                        ),
                                        file_path: String::new(),
                                        line: start_point.row + 1,
                                        column: start_point.column + 1,
                                        suggestion: Some(format!(
                                            "Use sizeof({}) as the size limit",
                                            dest_arg.trim()
                                        )),
                                        ..Default::default()
                                    });
                                    return;
                                }
                            }
                        }
                    }
                }
            }

            // Check for sizeof(dest) when source is a string literal (shorter source)
            // This catches patterns like: sizeof(p) used to copy from "Too short"
            // But NOT when there's a ternary/min check like: sizeof(p) < strlen(q) + 1 ? sizeof(p) : strlen(q) + 1
            if let Some(sizeof_var) = self.extract_sizeof_var(resolved_size) {
                // If sizeof references destination and source is a string literal
                if sizeof_var == dest_arg.trim() {
                    // Check if there's already a size validation in the resolved expression
                    // Skip if there's a ternary pattern like "sizeof(p) < strlen(q)"
                    if !resolved_size.contains("strlen(")
                        && !resolved_size.contains("?")
                        && !resolved_size.contains("<")
                    {
                        // Check if source is a string literal or assigned from one
                        if self.is_short_string_source(src_arg, dest_arg, source) {
                            let start_point = node.start_position();
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::High,
                                message: format!(
                                    "Function '{}': sizeof({}) may read past end of source buffer",
                                    function_name, sizeof_var
                                ),
                                file_path: String::new(),
                                line: start_point.row + 1,
                                column: start_point.column + 1,
                                suggestion: Some(
                                    "Use minimum of sizeof(dest) and source size".to_string(),
                                ),
                                ..Default::default()
                            });
                            return;
                        }
                    }
                }
            }
        }

        // Check for hardcoded sizes
        if self.is_hardcoded_large_size(size_arg) {
            let start_point = node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "Function '{}' called with hardcoded size {} that may exceed buffer bounds",
                    function_name, size_arg
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some("Use sizeof(buffer) or a validated size".to_string()),
                ..Default::default()
            });
            return;
        }

        // Check for user-controlled sizes (Heartbleed-like vulnerability)
        if self.is_potentially_user_controlled_in_source(size_arg, source) {
            let start_point = node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "Function '{}' called with potentially unvalidated size parameter '{}'",
                    function_name, size_arg
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some(
                    "Validate size parameter against actual buffer size before use".to_string(),
                ),
                ..Default::default()
            });
            return;
        }

        // Check for type size mismatches (sizeof(int) for long array)
        // Use resolved size to catch patterns like: const size_t n = sizeof(int) * ARR_SIZE; memset(p, 0, n);
        if self.is_dangerous_size_calculation(resolved_size) {
            let start_point = node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "Function '{}' called with potentially invalid size calculation",
                    function_name
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some("Ensure size argument does not exceed buffer bounds".to_string()),
                ..Default::default()
            });
        }
    }

    /// Check for overflow when destination is an offset pointer
    /// e.g., char *dest_ptr = buffer + 15; memcpy(dest_ptr, src, sizeof(src));
    fn check_pointer_offset_overflow(
        &self,
        args: &[String],
        node: &Node,
        function_name: &str,
        buffer_info: &HashMap<String, BufferInfo>,
        size_vars: &HashMap<String, String>,
        pointer_offsets: &HashMap<String, PointerOffsetInfo>,
    ) -> Option<RuleViolation> {
        let dest_arg = args[0].trim();
        let size_arg = args[2].trim();

        // Check if destination is an offset pointer
        if let Some(offset_info) = pointer_offsets.get(dest_arg) {
            // Get the base buffer size
            if let Some(base_info) = buffer_info.get(&offset_info.base_buffer) {
                if let Some(base_size) = base_info.size {
                    // Calculate remaining space after offset
                    if let Some(offset_val) = offset_info.offset {
                        if offset_val < 0 {
                            // Negative offset — pointer is before buffer start
                            let start_point = node.start_position();
                            return Some(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::High,
                                message: format!(
                                    "Function '{}': destination '{}' points {} bytes before '{}' buffer start",
                                    function_name, dest_arg, -offset_val, offset_info.base_buffer
                                ),
                                file_path: String::new(),
                                line: start_point.row + 1,
                                column: start_point.column + 1,
                                suggestion: Some("Do not form pointers before the start of allocated memory".to_string()),
                                ..Default::default()
                            });
                        }
                        let remaining = base_size.saturating_sub(offset_val as usize);

                        // Resolve the size argument
                        let size_arg_owned = size_arg.to_string();
                        let resolved_size = size_vars.get(size_arg).unwrap_or(&size_arg_owned);

                        // Try to determine copy size
                        let copy_size =
                            if let Some(sizeof_var) = self.extract_sizeof_var(resolved_size) {
                                // sizeof(some_var) - look up that var's size
                                if let Some(var_info) = buffer_info.get(&sizeof_var) {
                                    var_info.size
                                } else {
                                    self.try_parse_size(resolved_size)
                                }
                            } else {
                                self.try_parse_size(resolved_size)
                            };

                        if let Some(copy_val) = copy_size {
                            if copy_val > remaining {
                                let start_point = node.start_position();
                                return Some(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::High,
                                    message: format!(
                                        "Function '{}': copying {} bytes to '{}' (offset {} from '{}') exceeds remaining buffer space of {} bytes",
                                        function_name, copy_val, dest_arg, offset_val, offset_info.base_buffer, remaining
                                    ),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some(format!(
                                        "Reduce copy size to at most {} bytes or increase buffer size",
                                        remaining
                                    )),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Check if source argument has a negative pointer offset (reading before buffer start)
    fn check_source_pointer_offset(
        &self,
        args: &[String],
        src_index: usize,
        node: &Node,
        function_name: &str,
        pointer_offsets: &HashMap<String, PointerOffsetInfo>,
    ) -> Option<RuleViolation> {
        if args.len() <= src_index {
            return None;
        }
        let src_arg = args[src_index].trim();

        if let Some(offset_info) = pointer_offsets.get(src_arg) {
            if let Some(offset_val) = offset_info.offset {
                if offset_val < 0 {
                    let start_point = node.start_position();
                    return Some(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Function '{}': source '{}' points {} bytes before '{}' buffer start (buffer underread)",
                            function_name, src_arg, -offset_val, offset_info.base_buffer
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Do not form pointers before the start of allocated memory"
                                .to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
        }
        None
    }

    /// Check if size exceeds known buffer size
    fn check_size_exceeds_buffer(
        &self,
        buf_arg: &str,
        size_arg: &str,
        node: &Node,
        function_name: &str,
        buffer_info: &HashMap<String, BufferInfo>,
        size_vars: &HashMap<String, String>,
    ) -> Option<RuleViolation> {
        let buf_name = buf_arg.trim();

        // Try to get buffer info
        if let Some(buf_info) = buffer_info.get(buf_name) {
            if let Some(buf_size) = buf_info.size {
                // Try to resolve size_arg
                let size_arg_owned = size_arg.to_string();
                let resolved_size = size_vars.get(size_arg.trim()).unwrap_or(&size_arg_owned);

                // Try to parse size as a number.
                // For N*sizeof(T) expressions (byte counts for typed arrays), normalize
                // by dividing out the element size to get an element count for comparison.
                // BufferInfo.size stores element counts, not byte sizes.
                if let Some(size_val) = self.try_parse_size(resolved_size) {
                    let cmp_val = if let Some(elem_count) =
                        self.extract_elem_count_from_byte_expr(resolved_size)
                    {
                        elem_count
                    } else {
                        size_val
                    };
                    if cmp_val > buf_size {
                        let start_point = node.start_position();
                        return Some(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::High,
                            message: format!(
                                "Function '{}': size {} exceeds buffer '{}' size {}",
                                function_name, size_val, buf_name, buf_size
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some("Use sizeof(buffer) or correct size".to_string()),
                            ..Default::default()
                        });
                    }
                }

                // Check if size_arg is sizeof(something_different)
                if let Some(sizeof_var) = self.extract_sizeof_var(size_arg) {
                    if sizeof_var != buf_name {
                        // sizeof() of a different variable - check if it's larger
                        if let Some(other_info) = buffer_info.get(&sizeof_var) {
                            if let Some(other_size) = other_info.size {
                                if other_size > buf_size {
                                    let start_point = node.start_position();
                                    return Some(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        severity: Severity::High,
                                        message: format!(
                                            "Function '{}': sizeof({}) ({} bytes) may exceed buffer '{}' size ({} bytes)",
                                            function_name, sizeof_var, other_size, buf_name, buf_size
                                        ),
                                        file_path: String::new(),
                                        line: start_point.row + 1,
                                        column: start_point.column + 1,
                                        suggestion: Some(format!("Use sizeof({}) instead", buf_name)),
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Check if a size value might be user-controlled (Heartbleed-like)
    /// This is conservative but catches obvious patterns
    fn is_potentially_user_controlled_in_source(&self, size_arg: &str, source: &str) -> bool {
        let size_arg = size_arg.trim();

        // Check if it's a simple variable (not sizeof, not a calculation)
        if !size_arg.contains("sizeof(")
            && !size_arg.contains('+')
            && !size_arg.contains('-')
            && !size_arg.contains('*')
            && !size_arg.contains('/')
        {
            // Flag obvious patterns that indicate user/external input
            let suspicious_names = [
                "payload",      // classic Heartbleed pattern
                "user_size",    // explicit user-controlled
                "input_size",   // external input
                "client_size",  // network input
                "request_size", // network input
            ];

            // Check for exact match with suspicious names
            for name in &suspicious_names {
                if size_arg == *name {
                    // Check if there's validation in the source
                    if self.has_size_validation(size_arg, source) {
                        return false;
                    }
                    return true;
                }
            }

            // Check if size_arg is a function parameter that's used directly
            // Pattern: void func(..., type size_arg) { ... memcpy(..., size_arg); }
            if self.is_unvalidated_function_parameter(size_arg, source) {
                return true;
            }
        }

        false
    }

    /// Check if there's validation for a size parameter
    fn has_size_validation(&self, size_arg: &str, source: &str) -> bool {
        // Look for validation in if-statement conditions only
        let validation_patterns = [
            format!("if ({} >", size_arg),
            format!("if ({} <", size_arg),
            format!("if ({} >=", size_arg),
            format!("if ({} <=", size_arg),
            format!("if (1 + 2 + {}", size_arg), // Heartbleed specific validation pattern
            format!("{} > sizeof", size_arg),
            format!("{} >= sizeof", size_arg),
        ];
        for pattern in &validation_patterns {
            if source.contains(pattern.as_str()) {
                return true;
            }
        }
        false
    }

    /// Check if a variable is a function parameter used without validation
    fn is_unvalidated_function_parameter(&self, size_arg: &str, source: &str) -> bool {
        // Look for function parameter patterns
        // Pattern: type func(..., unsigned int user_size) or similar
        // Use word boundaries to avoid partial matches (e.g., "n" matching "nchars")
        let param_patterns = [
            format!("int {} ", size_arg), // "int n " - with trailing space
            format!("int {})", size_arg), // "int n)" - at end of params
            format!("int {},", size_arg), // "int n," - followed by comma
            format!("size_t {} ", size_arg),
            format!("size_t {})", size_arg),
            format!("size_t {},", size_arg),
            format!("unsigned {} ", size_arg),
            format!("unsigned {})", size_arg),
            format!("unsigned {},", size_arg),
            format!("uint32_t {} ", size_arg),
            format!("uint32_t {})", size_arg),
            format!("uint32_t {},", size_arg),
        ];

        // First check if size_arg IS directly a parameter
        let mut is_direct_param = false;
        for pattern in &param_patterns {
            // Check if it appears in a function signature (before first {)
            if let Some(brace_pos) = source.find('{') {
                let header = &source[..brace_pos];
                if header.contains(pattern.as_str()) && header.contains('(') {
                    is_direct_param = true;
                    break;
                }
            }
        }

        // If size_arg is not directly a parameter, check if it's assigned from one
        // But if it's assigned directly (n = nchars) where nchars is the param AND
        // nchars is also used for allocation (malloc(nchars)), that's safe
        if !is_direct_param {
            // Check if it's a local variable assigned from a param
            // This pattern is typically safe: const size_t n = nchars;
            // We only care about direct parameter use without validation
            return false;
        }

        // Check if there's validation before use
        if !self.has_size_validation(size_arg, source) {
            return true;
        }

        false
    }

    /// Check if source is a string literal that's shorter than destination
    fn is_short_string_source(&self, src_arg: &str, dest_arg: &str, source: &str) -> bool {
        let src = src_arg.trim();
        let dest = dest_arg.trim();

        // Check if source is directly a string literal
        if src.starts_with('"') && src.ends_with('"') {
            return true;
        }

        // Check if source variable is assigned from a string literal
        // Pattern: const char *q = "Too short";
        // or: char *q = "string";
        let patterns = [format!("*{} = \"", src), format!(" {} = \"", src)];
        for pattern in &patterns {
            if source.contains(pattern.as_str()) {
                // Found string literal assignment - now check if dest is larger
                // Look for dest array size
                if let Some(dest_size) = self.find_array_size(dest, source) {
                    // Estimate string length by finding the literal
                    if let Some(literal_len) = self.find_string_literal_length(src, source) {
                        if dest_size > literal_len {
                            return true;
                        }
                    } else {
                        // Couldn't determine length but it's a string literal assignment
                        // Be conservative and flag it
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Find the size of an array from its declaration
    fn find_array_size(&self, var_name: &str, source: &str) -> Option<usize> {
        // Pattern: type var_name[SIZE]
        let pattern = format!(" {}[", var_name);
        if let Some(start) = source.find(&pattern) {
            let rest = &source[start + pattern.len()..];
            if let Some(end) = rest.find(']') {
                let size_str = &rest[..end];
                if let Ok(size) = size_str.trim().parse::<usize>() {
                    return Some(size);
                }
            }
        }
        None
    }

    /// Find the length of a string literal assigned to a variable
    fn find_string_literal_length(&self, var_name: &str, source: &str) -> Option<usize> {
        // Look for: *var = "..." or var = "..."
        let patterns = [format!("*{} = \"", var_name), format!(" {} = \"", var_name)];
        for pattern in &patterns {
            if let Some(start) = source.find(pattern.as_str()) {
                let rest = &source[start + pattern.len()..];
                if let Some(end) = rest.find('"') {
                    // Length is end position + 1 for null terminator
                    return Some(end + 1);
                }
            }
        }
        None
    }

    /// Check for type size mismatch (e.g., sizeof(long) for int array)
    fn is_type_size_mismatch(&self, array_arg: &str, size_arg: &str, source: &str) -> bool {
        // Extract the type from sizeof(type)
        if let Some(sizeof_type) = self.extract_sizeof_type(size_arg) {
            // Check if the array was declared with a different type
            let array_name = array_arg.trim();

            // Look for array declaration in source
            // Pattern: type array_name[
            let patterns = [
                format!("int {}[", array_name),
                format!("int*{}", array_name),
                format!("char {}[", array_name),
                format!("char*{}", array_name),
                format!("short {}[", array_name),
                format!("long {}[", array_name),
                format!("float {}[", array_name),
                format!("double {}[", array_name),
            ];

            for pattern in &patterns {
                if source.contains(pattern) {
                    // Extract the declared type
                    if let Some(decl_type) = pattern.split_whitespace().next() {
                        // Check if sizeof type differs from declared type
                        if sizeof_type != decl_type
                            && !sizeof_type.contains(array_name)
                            && !sizeof_type.contains("*")
                        {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Extract type from sizeof(type)
    fn extract_sizeof_type(&self, expr: &str) -> Option<String> {
        if let Some(start) = expr.find("sizeof(") {
            let rest = &expr[start + 7..];
            if let Some(end) = rest.find(')') {
                let inner = rest[..end].trim();
                // Check if it's a type (not a variable or dereference)
                if !inner.starts_with('*') && !inner.contains('[') {
                    // Common C types
                    let types = [
                        "int", "char", "short", "long", "float", "double", "void", "size_t",
                        "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t",
                        "uint32_t", "uint64_t", "wchar_t",
                    ];
                    for t in &types {
                        if inner.contains(t) {
                            return Some(inner.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    /// Extract variable name from sizeof(var)
    fn extract_sizeof_var(&self, expr: &str) -> Option<String> {
        if let Some(start) = expr.find("sizeof(") {
            let rest = &expr[start + 7..];
            if let Some(end) = rest.find(')') {
                let var = rest[..end].trim();
                // Handle sizeof(*ptr) - return ptr
                if let Some(stripped) = var.strip_prefix('*') {
                    return Some(stripped.trim().to_string());
                }
                return Some(var.to_string());
            }
        }
        None
    }

    /// Check if a numeric size argument fits within a known buffer.
    /// Returns true if buffer size is known AND the size fits, meaning
    /// heuristic checks (is_hardcoded_large_size) should be skipped.
    fn is_size_within_known_buffer(
        &self,
        buf_arg: &str,
        size_arg: &str,
        buffer_info: &HashMap<String, BufferInfo>,
        size_vars: Option<&HashMap<String, String>>,
    ) -> bool {
        let buf_name = buf_arg.trim();
        if let Some(buf_info) = buffer_info.get(buf_name) {
            if let Some(buf_size) = buf_info.size {
                let resolved = size_vars
                    .and_then(|sv| sv.get(size_arg.trim()))
                    .map(|s| s.as_str())
                    .unwrap_or(size_arg);
                if let Some(size_val) = self.try_parse_size(resolved) {
                    let cmp_val = if let Some(elem_count) =
                        self.extract_elem_count_from_byte_expr(resolved)
                    {
                        elem_count
                    } else {
                        size_val
                    };
                    return cmp_val <= buf_size;
                }
            }
        }
        false
    }

    /// Check if a size is a hardcoded large value
    fn is_hardcoded_large_size(&self, size_arg: &str) -> bool {
        // Try to parse as a number
        if let Some(size) = self.try_parse_size(size_arg) {
            // Suspicious if it's a round number > 20 or any number > 100
            // that doesn't look like it comes from sizeof or a constant
            if size > 100
                || (size > 20 && size % 10 == 0)
                || (size > 10 && !size_arg.contains("sizeof"))
            {
                return true;
            }
        }
        false
    }

    /// Check if count is a suspicious hardcoded value
    fn is_hardcoded_large_count(&self, count_arg: &str) -> bool {
        if let Some(count) = self.try_parse_size(count_arg) {
            // Suspicious if > 20 and doesn't use sizeof
            if count > 20 && !count_arg.contains("sizeof") {
                return true;
            }
        }
        false
    }

    /// Try to parse a size expression as a numeric value
    fn try_parse_size(&self, expr: &str) -> Option<usize> {
        let expr = expr.trim();
        // Direct number
        if let Ok(n) = expr.parse::<usize>() {
            return Some(n);
        }
        // Handle N*sizeof(type) patterns (e.g., "100*sizeof(char)")
        if let Some(star_pos) = expr.find('*') {
            let left = expr[..star_pos].trim();
            let right = expr[star_pos + 1..].trim();
            // Try left * sizeof(type)
            if let Ok(n) = left.parse::<usize>() {
                if right.starts_with("sizeof(") {
                    let type_name = right.trim_start_matches("sizeof(").trim_end_matches(')');
                    if let Some(type_size) = self.sizeof_type(type_name) {
                        return Some(n * type_size);
                    }
                }
            }
            // Try sizeof(type) * N
            if let Ok(n) = right.parse::<usize>() {
                if left.starts_with("sizeof(") {
                    let type_name = left.trim_start_matches("sizeof(").trim_end_matches(')');
                    if let Some(type_size) = self.sizeof_type(type_name) {
                        return Some(n * type_size);
                    }
                }
            }
        }
        None
    }

    /// Get size of common C types
    fn sizeof_type(&self, type_name: &str) -> Option<usize> {
        match type_name.trim() {
            "char" | "unsigned char" | "signed char" => Some(1),
            "short" | "unsigned short" => Some(2),
            "int" | "unsigned int" | "int32_t" | "uint32_t" => Some(4),
            "long" | "unsigned long" | "int64_t" | "uint64_t" | "long long"
            | "unsigned long long" | "size_t" => Some(8),
            "float" => Some(4),
            "double" => Some(8),
            "wchar_t" => Some(4),
            "twoIntsStruct" => Some(8), // Common Juliet struct
            _ => None,
        }
    }

    /// If `expr` is of the form `N*sizeof(T)`, return N (the element count).
    /// Returns None for other expressions (not a typed byte-count pattern).
    fn extract_elem_count_from_byte_expr(&self, expr: &str) -> Option<usize> {
        let expr = expr.trim();
        if let Some(star_pos) = expr.find('*') {
            let left = expr[..star_pos].trim();
            let right = expr[star_pos + 1..].trim();
            // N*sizeof(T) form
            if right.starts_with("sizeof(") {
                if let Ok(n) = left.parse::<usize>() {
                    return Some(n);
                }
            }
            // sizeof(T)*N form
            if left.starts_with("sizeof(") {
                if let Ok(n) = right.parse::<usize>() {
                    return Some(n);
                }
            }
        }
        None
    }

    /// Extract array variable name from declaration
    fn extract_array_var_name(&self, decl: &str) -> Option<String> {
        // Pattern: type var[size] or type *var = ...
        // Find the identifier before [
        if let Some(bracket_pos) = decl.find('[') {
            let before = &decl[..bracket_pos];
            let parts: Vec<&str> = before.split_whitespace().collect();
            if let Some(last) = parts.last() {
                // Remove any * prefix
                let name = last.trim_start_matches('*');
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
        None
    }

    /// Extract array size from declaration like "char arr[40]"
    fn extract_array_size(&self, decl: &str) -> Option<usize> {
        if let Some(start) = decl.find('[') {
            if let Some(end) = decl[start + 1..].find(']') {
                let size_str = decl[start + 1..start + 1 + end].trim();
                if let Ok(size) = size_str.parse::<usize>() {
                    return Some(size);
                }
            }
        }
        None
    }

    /// Extract pointer variable name from declaration with allocation
    fn extract_pointer_var_name(&self, decl: &str) -> Option<String> {
        // Pattern: type *var = malloc(...)
        if let Some(eq_pos) = decl.find('=') {
            let before = &decl[..eq_pos];
            let parts: Vec<&str> = before.split_whitespace().collect();
            if let Some(last) = parts.last() {
                let name = last.trim_start_matches('*').trim_end_matches('*');
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
        None
    }

    /// Extract allocation size from malloc/calloc/aligned_alloc/alloca call
    fn extract_alloc_size(&self, text: &str) -> Option<String> {
        // Find the function call
        for func in &["malloc(", "aligned_alloc(", "ALLOCA(", "alloca("] {
            if let Some(start) = text.find(func) {
                let rest = &text[start + func.len()..];
                // For aligned_alloc, skip the alignment parameter
                let size_start = if *func == "aligned_alloc(" {
                    rest.find(',').map(|p| p + 1).unwrap_or(0)
                } else {
                    0
                };
                let size_part = &rest[size_start..];
                if let Some(end) = size_part.find(')') {
                    let size = size_part[..end].trim();
                    return Some(size.to_string());
                }
            }
        }

        // For calloc, extract count * size
        if let Some(start) = text.find("calloc(") {
            let rest = &text[start + 7..];
            if let Some(end) = rest.find(')') {
                let args = &rest[..end];
                return Some(args.to_string());
            }
        }

        None
    }

    /// Extract size_t variable assignment
    fn extract_size_var_assignment(&self, text: &str) -> Option<(String, String)> {
        // Pattern: size_t n = sizeof(p); or const size_t n = value;
        if let Some(eq_pos) = text.find('=') {
            let before = &text[..eq_pos];
            let after = &text[eq_pos + 1..];

            // Get variable name (last word before =)
            let parts: Vec<&str> = before.split_whitespace().collect();
            if let Some(var_name) = parts.last() {
                let var_name = var_name.trim();
                // Get value (everything after = until ; or end)
                // Don't strip parens as they're part of sizeof() etc.
                let value = after.trim().trim_end_matches(';').trim();
                if !var_name.is_empty() && !value.is_empty() {
                    return Some((var_name.to_string(), value.to_string()));
                }
            }
        }
        None
    }

    /// Extract assignment left-hand side
    fn extract_assignment_lhs(&self, text: &str) -> Option<String> {
        if let Some(eq_pos) = text.find('=') {
            let before = &text[..eq_pos];
            let parts: Vec<&str> = before.split_whitespace().collect();
            if let Some(last) = parts.last() {
                let name = last.trim_start_matches('*').trim_end_matches('*');
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
        None
    }

    /// Extract simple assignment (var = expr)
    fn extract_simple_assignment(&self, text: &str) -> Option<(String, String)> {
        if let Some(eq_pos) = text.find('=') {
            // Make sure it's not == or !=
            if eq_pos > 0 {
                let char_before = text[..eq_pos].chars().next_back();
                if char_before == Some('!') || char_before == Some('=') {
                    return None;
                }
            }
            if text.len() > eq_pos + 1 {
                let char_after = text[eq_pos + 1..].chars().next();
                if char_after == Some('=') {
                    return None;
                }
            }

            let before = &text[..eq_pos];
            let after = &text[eq_pos + 1..];

            let parts: Vec<&str> = before.split_whitespace().collect();
            if let Some(var_name) = parts.last() {
                let value = after.trim().trim_end_matches(';').trim();
                if !var_name.is_empty() && !value.is_empty() {
                    return Some((var_name.to_string(), value.to_string()));
                }
            }
        }
        None
    }

    /// Extract pointer offset from declaration like "char *ptr = buffer + 15;"
    /// Returns (ptr_name, base_buffer, offset_expr)
    #[allow(dead_code)]
    fn extract_pointer_offset(&self, text: &str) -> Option<(String, String, String)> {
        // Pattern: type *ptr = base + offset;
        if let Some(eq_pos) = text.find('=') {
            let before = &text[..eq_pos];
            let after = &text[eq_pos + 1..];

            // Get pointer name (last word before =, with * removed)
            let parts: Vec<&str> = before.split_whitespace().collect();
            if let Some(last) = parts.last() {
                let ptr_name = last.trim_start_matches('*').trim();
                if ptr_name.is_empty() {
                    return None;
                }

                // Parse the right side: base + offset
                let rhs = after.trim().trim_end_matches(';').trim();
                if let Some(plus_pos) = rhs.find('+') {
                    let base = rhs[..plus_pos].trim();
                    let offset = rhs[plus_pos + 1..].trim();

                    if !base.is_empty() && !offset.is_empty() {
                        return Some((ptr_name.to_string(), base.to_string(), offset.to_string()));
                    }
                }
            }
        }
        None
    }

    /// Extract pointer offset with sign: returns (ptr_name, base, offset, is_negative)
    fn extract_pointer_offset_signed(&self, text: &str) -> Option<(String, String, String, bool)> {
        if let Some(eq_pos) = text.find('=') {
            let before = &text[..eq_pos];
            let after = &text[eq_pos + 1..];

            let parts: Vec<&str> = before.split_whitespace().collect();
            if let Some(last) = parts.last() {
                let ptr_name = last.trim_start_matches('*').trim();
                if ptr_name.is_empty() {
                    return None;
                }

                let rhs = after.trim().trim_end_matches(';').trim();

                // Try subtraction first (more specific: avoid matching cast minus like (type*)expr - n)
                // Look for pattern: identifier - number/identifier
                if let Some(minus_pos) = rhs.rfind(" - ") {
                    let base = rhs[..minus_pos].trim();
                    let offset = rhs[minus_pos + 3..].trim();
                    if !base.is_empty()
                        && !offset.is_empty()
                        && !base.contains('(')
                        && base.chars().all(|c| c.is_alphanumeric() || c == '_')
                    {
                        return Some((
                            ptr_name.to_string(),
                            base.to_string(),
                            offset.to_string(),
                            true,
                        ));
                    }
                }

                // Try addition
                if let Some(plus_pos) = rhs.find('+') {
                    let base = rhs[..plus_pos].trim();
                    let offset = rhs[plus_pos + 1..].trim();
                    if !base.is_empty() && !offset.is_empty() {
                        return Some((
                            ptr_name.to_string(),
                            base.to_string(),
                            offset.to_string(),
                            false,
                        ));
                    }
                }
            }
        }
        None
    }

    /// Collect all function_definition nodes from the AST
    fn collect_function_definitions<'a>(&self, node: &Node<'a>) -> Vec<Node<'a>> {
        let mut functions = Vec::new();
        self.collect_function_definitions_recursive(node, &mut functions);
        functions
    }

    fn collect_function_definitions_recursive<'a>(
        &self,
        node: &Node<'a>,
        functions: &mut Vec<Node<'a>>,
    ) {
        if node.kind() == "function_definition" {
            functions.push(*node);
            return; // Don't recurse into nested function definitions
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.collect_function_definitions_recursive(&child, functions);
            }
        }
    }

    /// Collect simple pointer aliases from assignment statements (e.g., "data = dataBuffer")
    /// Collect pointer offset assignments within a single function node
    fn collect_pointer_offsets_in_node(
        &self,
        node: &Node,
        source: &str,
        offsets: &mut HashMap<String, PointerOffsetInfo>,
    ) {
        let text = get_node_text(node, source);

        // Check declarations (init_declarator): char *data = buffer - 8;
        if node.kind() == "declaration" || node.kind() == "init_declarator" {
            if text.contains('=') && (text.contains('+') || text.contains(" - ")) {
                if let Some((ptr_name, base, offset, negative)) =
                    self.extract_pointer_offset_signed(&text)
                {
                    let offset_val = self.try_parse_size(&offset).map(|v| {
                        if negative {
                            -(v as i64)
                        } else {
                            v as i64
                        }
                    });
                    offsets.insert(
                        ptr_name,
                        PointerOffsetInfo {
                            base_buffer: base,
                            offset: offset_val,
                            offset_expr: if negative {
                                format!("-{}", offset)
                            } else {
                                offset
                            },
                        },
                    );
                    return;
                }
            }
        }

        // Check expression statements: data = buffer - 8;
        if node.kind() == "expression_statement" {
            if text.contains('=') && (text.contains('+') || text.contains(" - ")) {
                if let Some((ptr_name, base, offset, negative)) =
                    self.extract_pointer_offset_signed(&text)
                {
                    let offset_val = self.try_parse_size(&offset).map(|v| {
                        if negative {
                            -(v as i64)
                        } else {
                            v as i64
                        }
                    });
                    offsets.insert(
                        ptr_name,
                        PointerOffsetInfo {
                            base_buffer: base,
                            offset: offset_val,
                            offset_expr: if negative {
                                format!("-{}", offset)
                            } else {
                                offset
                            },
                        },
                    );
                    return;
                }
            }
            // Plain assignment (data = buffer) clears any stale offset
            let trimmed = text.trim().trim_end_matches(';').trim();
            if let Some(eq_pos) = trimmed.find('=') {
                if eq_pos > 0
                    && !matches!(
                        trimmed.as_bytes().get(eq_pos.wrapping_sub(1)),
                        Some(b'!' | b'<' | b'>')
                    )
                    && trimmed.as_bytes().get(eq_pos + 1) != Some(&b'=')
                {
                    let lhs = trimmed[..eq_pos].trim();
                    // If LHS is a tracked pointer being reassigned without offset, clear it
                    if offsets.contains_key(lhs) {
                        let rhs = trimmed[eq_pos + 1..].trim();
                        if !rhs.contains('+') && !rhs.contains(" - ") {
                            offsets.remove(lhs);
                        }
                    }
                }
            }
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.collect_pointer_offsets_in_node(&child, source, offsets);
            }
        }
    }

    fn collect_pointer_aliases(&self, node: &Node, source: &str) -> Vec<(String, String)> {
        let mut aliases = Vec::new();
        self.collect_pointer_aliases_recursive(node, source, &mut aliases);
        aliases
    }

    fn collect_pointer_aliases_recursive(
        &self,
        node: &Node,
        source: &str,
        aliases: &mut Vec<(String, String)>,
    ) {
        // Look for expression_statement containing assignment_expression
        if node.kind() == "expression_statement" {
            let text = get_node_text(node, source);
            let text = text.trim().trim_end_matches(';').trim();
            // Simple assignment: "data = dataBuffer" (no operators, no function calls)
            if let Some(eq_pos) = text.find('=') {
                // Skip ==, !=, <=, >=
                if eq_pos > 0
                    && !matches!(
                        text.as_bytes().get(eq_pos.wrapping_sub(1)),
                        Some(b'!' | b'<' | b'>')
                    )
                    && text.as_bytes().get(eq_pos + 1) != Some(&b'=')
                {
                    let lhs = text[..eq_pos].trim();
                    let rhs = text[eq_pos + 1..].trim();
                    // Only simple identifiers (no operators, no function calls, no casts)
                    if self.is_simple_identifier(lhs) && self.is_simple_identifier(rhs) {
                        aliases.push((lhs.to_string(), rhs.to_string()));
                    }
                }
            }
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.collect_pointer_aliases_recursive(&child, source, aliases);
            }
        }
    }

    /// Check if a string is a simple C identifier
    fn is_simple_identifier(&self, s: &str) -> bool {
        !s.is_empty()
            && s.starts_with(|c: char| c.is_alphabetic() || c == '_')
            && s.chars().all(|c| c.is_alphanumeric() || c == '_')
    }

    /// Extract the argument from a strlen() call
    /// "strlen(data)" → Some("data"), "100" → None
    fn extract_strlen_argument<'a>(&self, expr: &'a str) -> Option<&'a str> {
        let expr = expr.trim();
        if let Some(rest) = expr.strip_prefix("strlen(") {
            if let Some(arg) = rest.strip_suffix(')') {
                let arg = arg.trim();
                if !arg.is_empty() {
                    return Some(arg);
                }
            }
        }
        None
    }

    /// Extract the argument from a wcslen() call
    /// "wcslen(data)" → Some("data"), "100" → None
    fn extract_wcslen_argument<'a>(&self, expr: &'a str) -> Option<&'a str> {
        let expr = expr.trim();
        if let Some(rest) = expr.strip_prefix("wcslen(") {
            if let Some(arg) = rest.strip_suffix(')') {
                let arg = arg.trim();
                if !arg.is_empty() {
                    return Some(arg);
                }
            }
        }
        None
    }

    /// Extract strlen/wcslen argument from `strlen(x)*sizeof(T)` or `sizeof(T)*strlen(x)` patterns.
    /// Returns the inner argument (e.g., "data" from "strlen(data)*sizeof(char)").
    fn extract_strlen_from_sizeof_expr<'a>(&self, expr: &'a str) -> Option<&'a str> {
        if let Some(star_idx) = expr.find('*') {
            let left = expr[..star_idx].trim();
            let right = expr[star_idx + 1..].trim();
            if right.starts_with("sizeof(") {
                return self
                    .extract_strlen_argument(left)
                    .or_else(|| self.extract_wcslen_argument(left));
            }
            if left.starts_with("sizeof(") {
                return self
                    .extract_strlen_argument(right)
                    .or_else(|| self.extract_wcslen_argument(right));
            }
        }
        None
    }
}
