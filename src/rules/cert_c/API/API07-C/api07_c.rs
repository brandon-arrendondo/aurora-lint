//! API07-C: Enforce type safety
//!
//! Detects two patterns:
//! 1. **strncpy without null-termination**: `strncpy()` does not guarantee
//!    null-termination of the destination buffer.
//! 2. **Free pointer not at start of buffer (CWE-761)**: `free(p)` where `p`
//!    was modified by pointer arithmetic after allocation. The pointer must
//!    point to the start of the allocated block when passed to `free()`.

use crate::manifest::{RuleCategory, Severity};
use crate::rules::{CertRule, RuleViolation};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Api07C;

impl CertRule for Api07C {
    fn rule_id(&self) -> &'static str {
        "API07-C"
    }

    fn description(&self) -> &'static str {
        "Enforce type safety"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "API07-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_strncpy_call(&call, source, &mut violations);
        }

        // Check each function for free-not-at-start and type confusion patterns
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_free_not_at_start(&func, source, &mut violations);
            self.check_type_confusion(&func, source, &mut violations);
        }
        violations
    }
}

impl Api07C {
    fn check_strncpy_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = get_node_text(&function_node, source);
            if function_name == "strncpy" {
                let start_point = node.start_position();
                let call_text = get_node_text(node, source);
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "Use of strncpy() '{}' does not guarantee null-termination, violating type safety",
                        call_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some(
                        "Use strncpy_s() (C11 Annex K) or manually null-terminate the destination buffer".to_string()
                    ),
                    ..Default::default()
                });
            }
        }
    }

    /// CWE-761: Detect free() on a pointer that was modified after allocation.
    ///
    /// Scans the function body text for:
    /// 1. Allocation: `var = malloc(...)` / `var = (T*)malloc(...)` / `var = calloc(...)`
    /// 2. Modification: `var++` / `var--` / `var +=` / `var -=` / `var = var +` / `var = var -`
    /// 3. Free: `free(var)` after modification
    fn check_free_not_at_start(
        &self,
        func_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let func_text = get_node_text(func_node, source);
        let func_start_row = func_node.start_position().row;

        // Find all allocated pointer variables
        let allocated_vars = self.find_allocated_vars(&func_text);
        if allocated_vars.is_empty() {
            return;
        }

        // For each allocated var, check if it's modified then freed
        for var in &allocated_vars {
            let mut modified = false;

            for (line_idx, line) in func_text.lines().enumerate() {
                let trimmed = line.trim();

                // Check for reassignment back to allocation (resets modification tracking)
                if self.is_allocation_of(trimmed, var) {
                    modified = false;
                    continue;
                }

                // Check for pointer modification
                if !modified && self.is_pointer_modification(trimmed, var) {
                    modified = true;
                }

                // Check for free() on modified pointer
                if modified && self.is_free_of(trimmed, var) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Calling free({}) after pointer arithmetic. The pointer may not point to the start of the allocated block.",
                            var
                        ),
                        file_path: String::new(),
                        line: func_start_row + line_idx + 1,
                        column: 1,
                        suggestion: Some(
                            "Save the original pointer before modifying it, and pass the original to free().".to_string()
                        ),
                        ..Default::default()
                    });
                    break; // One violation per var per function
                }

                // Reset if var is reassigned to something else entirely
                if modified && self.is_reassignment_of(trimmed, var) {
                    modified = false;
                }
            }
        }
    }

    /// CWE-843: Detect type confusion through void* pointers.
    ///
    /// Pattern: void* data = &smallVar; ... *((int*)data)
    /// where smallVar is a smaller type (char, short) than the cast target (int).
    fn check_type_confusion(
        &self,
        func_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let func_text = get_node_text(func_node, source);
        let func_start_row = func_node.start_position().row;

        // Phase 1: Find void* variable declarations
        let mut void_ptr_vars: HashSet<String> = HashSet::new();
        // Maps variable name → declared type (e.g., "charBuffer" → "char")
        let mut var_types: HashMap<String, String> = HashMap::new();
        // Maps void* var → source type it was assigned from
        let mut void_ptr_source_type: HashMap<String, String> = HashMap::new();

        for line in func_text.lines() {
            let trimmed = line.trim();

            // Detect void* declarations: "void * data" or "void *data"
            if (trimmed.contains("void *") || trimmed.contains("void*"))
                && !trimmed.starts_with("//")
                && !trimmed.starts_with("/*")
            {
                // Extract the variable name after void * / void*
                if let Some(name) = Self::extract_void_ptr_var(trimmed) {
                    void_ptr_vars.insert(name);
                }
            }

            // Track typed variable declarations for type lookup
            for type_name in &["char", "short", "int", "long", "float", "double"] {
                if let Some(var_name) = Self::extract_typed_var(trimmed, type_name) {
                    var_types.insert(var_name, type_name.to_string());
                }
            }
        }

        if void_ptr_vars.is_empty() {
            return;
        }

        // Phase 2: Track assignments and detect confusion
        for (line_idx, line) in func_text.lines().enumerate() {
            let trimmed = line.trim();

            // Track assignments: data = &varName
            for vp in &void_ptr_vars {
                let assign_pat = format!("{} = &", vp);
                if let Some(pos) = trimmed.find(&assign_pat) {
                    let after = &trimmed[pos + assign_pat.len()..];
                    let var_name: String = after
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if let Some(src_type) = var_types.get(&var_name) {
                        void_ptr_source_type.insert(vp.clone(), src_type.clone());
                    }
                }
            }

            // Detect dereference with cast: *((int*)data) or *((long*)data)
            for vp in &void_ptr_vars {
                if let Some(src_type) = void_ptr_source_type.get(vp) {
                    if let Some(cast_type) = Self::find_cast_deref(trimmed, vp) {
                        if Self::type_size(&cast_type) > Self::type_size(src_type) {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::High,
                                message: format!(
                                    "Type confusion: void* '{}' points to {} but is dereferenced as {}*",
                                    vp, src_type, cast_type
                                ),
                                file_path: String::new(),
                                line: func_start_row + line_idx + 1,
                                column: 1,
                                suggestion: Some(
                                    "Ensure the cast type matches the actual pointed-to type"
                                        .to_string(),
                                ),
                                ..Default::default()
                            });
                            break;
                        }
                    }
                }
            }
        }
    }

    fn extract_void_ptr_var(line: &str) -> Option<String> {
        // Match patterns: "void * name", "void *name", "void * name ="
        let patterns = ["void * ", "void *"];
        for pat in &patterns {
            if let Some(pos) = line.find(pat) {
                let after = line[pos + pat.len()..].trim_start();
                let name: String = after
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() && name.chars().next().is_some_and(|c| c.is_alphabetic()) {
                    return Some(name);
                }
            }
        }
        None
    }

    fn extract_typed_var(line: &str, type_name: &str) -> Option<String> {
        // Match: "char varName" or "char varName =" or "char varName;"
        // Avoid matching inside other tokens (e.g., "wchar_t")
        let pat = format!("{} ", type_name);
        if let Some(pos) = line.find(&pat) {
            // Make sure it's at a word boundary (start of line, after space, or after type qualifier)
            if pos > 0 {
                let prev = line.as_bytes()[pos - 1];
                if prev.is_ascii_alphanumeric() || prev == b'_' {
                    return None;
                }
            }
            let after = line[pos + pat.len()..].trim_start();
            let name: String = after
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty()
                && name.chars().next().is_some_and(|c| c.is_alphabetic())
                && !matches!(
                    name.as_str(),
                    "const" | "volatile" | "static" | "extern" | "register"
                )
            {
                return Some(name);
            }
        }
        None
    }

    /// Find a cast-dereference pattern like *((int*)var) or *((long *)var)
    fn find_cast_deref(line: &str, var_name: &str) -> Option<String> {
        // Look for patterns: (TYPE*)var or (TYPE *)var followed by ) and preceded by *(
        let var_close = format!("{})", var_name);
        if !line.contains(&var_close) {
            return None;
        }

        // Find cast type: look for (TYPE*) or (TYPE *) before var_name
        let search = format!("*){}", var_name);
        if let Some(pos) = line.find(&search) {
            // Walk backwards from pos to find the opening ( of the cast
            let before = &line[..pos];
            if let Some(paren_pos) = before.rfind('(') {
                let cast_content = before[paren_pos + 1..].trim();
                // Extract type name (everything before the *)
                let type_name: String = cast_content.trim_end_matches('*').trim().to_string();
                if !type_name.is_empty() {
                    return Some(type_name);
                }
            }
        }

        // Also handle (TYPE *) with space before *
        let search2 = format!(" *){}", var_name);
        if let Some(pos) = line.find(&search2) {
            let before = &line[..pos];
            if let Some(paren_pos) = before.rfind('(') {
                let type_name = before[paren_pos + 1..].trim().to_string();
                if !type_name.is_empty() {
                    return Some(type_name);
                }
            }
        }

        None
    }

    fn type_size(type_name: &str) -> usize {
        match type_name {
            "char" | "signed char" | "unsigned char" => 1,
            "short" | "signed short" | "unsigned short" => 2,
            "int" | "signed int" | "unsigned int" | "signed" | "unsigned" => 4,
            "long" | "signed long" | "unsigned long" => 8,
            "float" => 4,
            "double" => 8,
            _ => 0, // Unknown type — don't flag
        }
    }

    fn find_allocated_vars(&self, func_text: &str) -> HashSet<String> {
        let mut vars = HashSet::new();
        for line in func_text.lines() {
            let trimmed = line.trim();
            // Match: var = malloc(...), var = (T*)malloc(...), var = calloc(...)
            // Also match: var = (T *)realloc(...)
            if let Some(var) = self.extract_alloc_target(trimmed) {
                vars.insert(var);
            }
        }
        vars
    }

    fn extract_alloc_target(&self, line: &str) -> Option<String> {
        // Look for pattern: IDENT = ... malloc/calloc/realloc(
        let eq_pos = line.find('=')?;
        let before_eq = line[..eq_pos].trim();
        let after_eq = line[eq_pos + 1..].trim();

        // Skip ==, !=, <=, >=
        if line.len() > eq_pos + 1 {
            let next = line.as_bytes().get(eq_pos + 1)?;
            if *next == b'=' {
                return None;
            }
        }
        if eq_pos > 0 && matches!(line.as_bytes()[eq_pos - 1], b'!' | b'<' | b'>') {
            return None;
        }

        // Check if RHS contains an allocation call
        if !after_eq.contains("malloc(")
            && !after_eq.contains("calloc(")
            && !after_eq.contains("realloc(")
        {
            return None;
        }

        // Extract the variable name (last token before =)
        let var_name = before_eq.split_whitespace().last()?.trim_start_matches('*');

        if var_name.chars().all(|c| c.is_alphanumeric() || c == '_')
            && !var_name.is_empty()
            && var_name.chars().next()?.is_alphabetic()
        {
            Some(var_name.to_string())
        } else {
            None
        }
    }

    fn is_allocation_of(&self, line: &str, var: &str) -> bool {
        // var = ...malloc/calloc/realloc(
        if let Some(eq_pos) = line.find('=') {
            if eq_pos > 0 && line.as_bytes()[eq_pos - 1] != b'!' {
                let before = line[..eq_pos].trim();
                let after = line[eq_pos + 1..].trim();
                let last_token = before.split_whitespace().last().unwrap_or("");
                let last_token = last_token.trim_start_matches('*');
                if last_token == var
                    && (after.contains("malloc(")
                        || after.contains("calloc(")
                        || after.contains("realloc("))
                {
                    return true;
                }
            }
        }
        false
    }

    fn is_pointer_modification(&self, line: &str, var: &str) -> bool {
        // var++ or var--
        if line.contains(&format!("{}++", var)) || line.contains(&format!("{}--", var)) {
            return true;
        }
        // ++var or --var
        if line.contains(&format!("++{}", var)) || line.contains(&format!("--{}", var)) {
            return true;
        }
        // var += or var -=
        if line.contains(&format!("{} +=", var)) || line.contains(&format!("{} -=", var)) {
            return true;
        }
        // for(...; ...; var++) pattern
        if line.starts_with("for")
            && (line.contains(&format!("{}++", var)) || line.contains(&format!("{}--", var)))
        {
            return true;
        }
        false
    }

    fn is_free_of(&self, line: &str, var: &str) -> bool {
        line.contains(&format!("free({})", var)) || line.contains(&format!("free( {} )", var))
    }

    fn is_reassignment_of(&self, line: &str, var: &str) -> bool {
        // var = something (but not var == or var +=/-=)
        let pattern = format!("{} = ", var);
        if let Some(pos) = line.find(&pattern) {
            let after = &line[pos + pattern.len()..];
            // Not var = var + N (that's still modification, not reset)
            if !after.trim_start().starts_with(var) {
                return true;
            }
        }
        false
    }
}
