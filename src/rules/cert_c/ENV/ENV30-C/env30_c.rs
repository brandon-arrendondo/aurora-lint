// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use crate::analyze::argument_objects::argument_nodes;
use crate::manifest::{RuleCategory, Severity};
use crate::prelude::RuleViolation;
use crate::rules::cert_c::CertRule;
use crate::utility::cert_c::ast_utils::{get_node_text, resolve_identifier_declarator};
use crate::utility::cert_c::call_roles;
use crate::utility::cert_c::fn_ptr_bindings;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct ENV30C;

impl CertRule for ENV30C {
    fn rule_id(&self) -> &'static str {
        "ENV30-C"
    }

    fn cert_id(&self) -> &'static str {
        "ENV30"
    }

    fn description(&self) -> &'static str {
        "Do not modify the object referenced by the return value of certain functions"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl ENV30C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // A function pointer is bound where the file finds it convenient, not
        // where it is called: lua declares `l_getenv` at file scope, binds it
        // in `pmain` and calls it from `lua_initreadline`. So the bindings are
        // collected once over the whole translation unit, before any function
        // is walked.
        let fn_ptr_bindings = fn_ptr_bindings::file_scope_function_pointer_bindings(node, source);

        // Check function definitions to track variable assignments from protected functions
        for n in query::find_descendants_of_kind(*node, "function_definition") {
            violations.extend(self.check_function_for_violations(&n, source, &fn_ptr_bindings));
        }
    }

    fn check_function_for_violations(
        &self,
        func_node: &Node,
        source: &str,
        fn_ptr_bindings: &HashMap<String, Vec<String>>,
    ) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let mut protected_vars: HashMap<String, String> = HashMap::new();

        // Collect all variable assignments from protected functions
        self.collect_protected_assignments(func_node, source, fn_ptr_bindings, &mut protected_vars);

        // Check for modifications to those variables
        self.check_protected_var_modifications(func_node, source, &protected_vars, &mut violations);

        violations
    }

    fn collect_protected_assignments(
        &self,
        node: &Node,
        source: &str,
        fn_ptr_bindings: &HashMap<String, Vec<String>>,
        protected_vars: &mut HashMap<String, String>,
    ) {
        for n in query::find_descendants(*node, |_| true) {
            // Look for declarations like: char *env = getenv("X");
            if n.kind() == "declaration" {
                // Find if there's a protected function call
                if let Some(func_name) =
                    self.find_protected_function_call(&n, source, fn_ptr_bindings)
                {
                    // Extract variable name
                    if let Some(var_name) = self.extract_var_name_from_declaration(&n, source) {
                        protected_vars.insert(declared_key(&var_name, &n), func_name);
                    }
                }
                // Also check for derived pointers: char *ptr = strchr(protected_var, '.')
                else if let Some((derived_var, orig_func)) =
                    self.check_derived_pointer_declaration(&n, source, protected_vars)
                {
                    protected_vars.insert(
                        declared_key(&derived_var, &n),
                        format!("{} (derived)", orig_func),
                    );
                }
            }

            // Also handle assignment expressions (reassignment)
            if n.kind() == "assignment_expression" {
                if let Some(func_name) =
                    self.find_protected_function_call(&n, source, fn_ptr_bindings)
                {
                    // Extract variable name from left side
                    if let Some(left) = n.child_by_field_name("left") {
                        let var_name = get_node_text(&left, source).trim().to_string();
                        if !var_name.is_empty() {
                            protected_vars.insert(scoped_key(&left, &var_name, source), func_name);
                        }
                    }
                }
                // Also check for derived pointers
                else if let Some((derived_var, orig_func)) =
                    self.check_derived_pointer_assignment(&n, source, protected_vars)
                {
                    protected_vars.insert(derived_var, format!("{} (derived)", orig_func));
                }
                // Check for pointer aliasing: p = protected_var
                else if let Some((alias_var, orig_func)) =
                    self.check_pointer_alias(&n, source, protected_vars)
                {
                    protected_vars.insert(alias_var, format!("{} (alias)", orig_func));
                }
            }

            // Handle pointer aliases in init_declarator: char *p = protected_var
            if n.kind() == "init_declarator" {
                if let Some((alias_var, orig_func)) =
                    self.check_init_declarator_alias(&n, source, protected_vars)
                {
                    protected_vars.insert(alias_var, format!("{} (alias)", orig_func));
                }
            }
        }
    }

    /// Check if this declaration creates a derived pointer from a protected variable
    /// e.g., char *dot = strchr(lang, '.') where lang is protected
    fn check_derived_pointer_declaration(
        &self,
        node: &Node,
        source: &str,
        protected_vars: &HashMap<String, String>,
    ) -> Option<(String, String)> {
        let orig_func = self.derived_pointer_provenance(node, source, protected_vars)?;
        let var_name = self.extract_var_name_from_declaration(node, source)?;
        Some((var_name, orig_func))
    }

    /// Check if this assignment creates a derived pointer from a protected variable
    fn check_derived_pointer_assignment(
        &self,
        node: &Node,
        source: &str,
        protected_vars: &HashMap<String, String>,
    ) -> Option<(String, String)> {
        let orig_func = self.derived_pointer_provenance(node, source, protected_vars)?;
        let left = node.child_by_field_name("left")?;
        let var_name = get_node_text(&left, source).trim().to_string();
        Some((scoped_key(&left, &var_name, source), orig_func))
    }

    /// The provenance a derived pointer inherits: `strchr` and its
    /// neighbours return a pointer INTO the object they are handed, so
    /// `strchr(env, '=')` where `env` came from `getenv()` points into the
    /// environment string and writing through it is the same violation.
    ///
    /// Resolved on the AST, for the reason
    /// [`Self::find_protected_function_call`] documents at length: the pair
    /// of text scans this replaced asked whether the node's source range
    /// contained `strchr(` and then whether it contained `strchr(env,`,
    /// and a node's range includes its comments and its longer identifiers,
    /// so a `/* like strchr(p, c) */` or a call to some `utf8_strchr` read
    /// as the real thing. Nothing was observed firing from it on the
    /// current corpora -- this is the same bug class in the same file,
    /// closed before it costs a finding.
    ///
    /// Matching the argument as a node rather than as text also drops the
    /// four spelling patterns the old check enumerated: a call split
    /// across lines, or written `strchr( env , '=')`, is one AST either
    /// way.
    fn derived_pointer_provenance(
        &self,
        node: &Node,
        source: &str,
        protected_vars: &HashMap<String, String>,
    ) -> Option<String> {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            let Some(func) = call.child_by_field_name("function") else {
                continue;
            };
            if func.kind() != "identifier"
                || !self.is_pointer_returning_function(get_node_text(&func, source))
            {
                continue;
            }
            let Some(args) = call.child_by_field_name("arguments") else {
                continue;
            };
            // The first argument is the object searched; a protected
            // variable in any later position (the needle) is only read.
            let Some(first) = argument_nodes(&args).into_iter().next() else {
                continue;
            };
            if first.kind() != "identifier" {
                continue;
            }
            let name = get_node_text(&first, source);
            if let Some(orig_func) = protected_vars.get(&scoped_key(&first, name, source)) {
                return Some(orig_func.clone());
            }
        }
        None
    }

    /// Check if assignment is a direct pointer alias: alias = protected_var
    fn check_pointer_alias(
        &self,
        node: &Node,
        source: &str,
        protected_vars: &HashMap<String, String>,
    ) -> Option<(String, String)> {
        if let Some(left) = node.child_by_field_name("left") {
            if let Some(right) = node.child_by_field_name("right") {
                let right_text = get_node_text(&right, source).trim().to_string();
                // Check if right side is a protected variable (direct assignment)
                if right.kind() != "identifier" {
                    return None;
                }
                if let Some(orig_func) =
                    protected_vars.get(&scoped_key(&right, &right_text, source))
                {
                    let alias_name = get_node_text(&left, source).trim().to_string();
                    if !alias_name.is_empty() && alias_name != right_text {
                        return Some((scoped_key(&left, &alias_name, source), orig_func.clone()));
                    }
                }
            }
        }
        None
    }

    /// Check if init_declarator creates an alias: char *p = protected_var
    fn check_init_declarator_alias(
        &self,
        node: &Node,
        source: &str,
        protected_vars: &HashMap<String, String>,
    ) -> Option<(String, String)> {
        // Look for value field (the initializer)
        if let Some(value) = node.child_by_field_name("value") {
            let value_text = get_node_text(&value, source).trim().to_string();
            // Check if value is a protected variable
            if value.kind() != "identifier" {
                return None;
            }
            if let Some(orig_func) = protected_vars.get(&scoped_key(&value, &value_text, source)) {
                // Get the variable name being declared
                if let Some(decl) = node.child_by_field_name("declarator") {
                    let alias_name = self.extract_identifier_from_declarator(&decl, source);
                    if !alias_name.is_empty() && alias_name != value_text {
                        let declaration = node.parent().unwrap_or(*node);
                        return Some((declared_key(&alias_name, &declaration), orig_func.clone()));
                    }
                }
            }
        }
        None
    }

    /// Find a call to a protected function inside `node`, resolved on the AST.
    ///
    /// The text scan this replaced asked whether the node's source range
    /// contained `getenv(` anywhere, and a node's range includes its
    /// COMMENTS. sqlite's `azDirs` table documents each slot with
    /// `0, /* getenv("SQLITE_TMPDIR") */`, which seeded the whole array as
    /// getenv-provenance and made the very line that fills it
    /// (`azDirs[0] = osGetenv(...)`, a pointer store into an array element)
    /// report as a modification of the returned string -- five findings in
    /// os_win.c, all of them naming a construct that is not there
    /// (ADR-0005).
    ///
    /// Matching a `call_expression` whose `function` is exactly one of the
    /// protected identifiers fixes both halves at once: a comment is not a
    /// call, and `osGetenv` is not `getenv`. Returns the first such call in
    /// source order rather than in protected-list order, which is what a
    /// reader of the line expects when a node holds more than one.
    fn find_protected_function_call(
        &self,
        node: &Node,
        source: &str,
        fn_ptr_bindings: &HashMap<String, Vec<String>>,
    ) -> Option<String> {
        for call in stored_values(node)
            .into_iter()
            .flat_map(value_calls)
            .collect::<Vec<_>>()
        {
            let func = match call.child_by_field_name("function") {
                Some(f) => f,
                None => continue,
            };
            if func.kind() != "identifier" {
                continue;
            }
            let name = get_node_text(&func, source);
            if self.is_protected_function(name) {
                return Some(name.to_string());
            }
            if let Some(bound) =
                self.protected_through_pointer(&func, name, source, fn_ptr_bindings)
            {
                return Some(bound);
            }
        }
        None
    }

    /// The protected function a call through a function POINTER may reach.
    ///
    /// lua's `lua.c` declares `static char *(*l_getenv)(const char *);` and
    /// binds it to `&no_getenv` under `-E` and to `&getenv` otherwise, then
    /// calls it as `l_getenv(...)`. On the `&getenv` path the returned
    /// pointer is a protected object like any other, and the old text scan
    /// credited it only by accident -- the spelling `l_getenv` happens to
    /// contain `getenv`.
    ///
    /// MAY, not MUST: one binding being protected is enough, because that
    /// path exists. The occurrence is resolved to its declaration first, so
    /// a local of the same name cannot borrow the global's provenance
    /// (ADR-0006).
    fn protected_through_pointer(
        &self,
        func: &Node,
        name: &str,
        source: &str,
        fn_ptr_bindings: &HashMap<String, Vec<String>>,
    ) -> Option<String> {
        if !fn_ptr_bindings::call_resolves_to_file_scope_pointer(
            func,
            name,
            source,
            fn_ptr_bindings,
        ) {
            return None;
        }
        fn_ptr_bindings
            .get(name)?
            .iter()
            .find(|target| self.is_protected_function(target))
            .cloned()
    }

    fn extract_var_name_from_declaration(&self, node: &Node, source: &str) -> Option<String> {
        // Look for init_declarator nodes
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "init_declarator" {
                // Find the declarator (could be pointer_declarator or identifier)
                if let Some(decl) = child.child_by_field_name("declarator") {
                    return Some(self.extract_identifier_from_declarator(&decl, source));
                }
            }
        }
        None
    }

    fn extract_identifier_from_declarator(&self, node: &Node, source: &str) -> String {
        if node.kind() == "identifier" {
            return get_node_text(node, source).to_string();
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            let id = self.extract_identifier_from_declarator(&child, source);
            if !id.is_empty() {
                return id;
            }
        }

        String::new()
    }

    fn check_protected_var_modifications(
        &self,
        node: &Node,
        source: &str,
        protected_vars: &HashMap<String, String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants(*node, |_| true) {
            // Check for assignments that modify memory pointed to by protected variables
            if n.kind() == "assignment_expression" {
                if let Some(left) = n.child_by_field_name("left") {
                    // Only flag modifications through the pointer, not reassignment of the pointer itself
                    // e.g., `env[0] = 'X'` or `*env = 'X'` or `conv->field = x` should flag
                    // but `env = something_else` should NOT flag (that's just reassigning the pointer)
                    let left_kind = left.kind();
                    if left_kind == "subscript_expression"
                        || left_kind == "pointer_expression"
                        || left_kind == "field_expression"
                    {
                        if let Some((var_name, func_name)) =
                            self.get_protected_var_ref(&left, source, protected_vars)
                        {
                            let start = n.start_position();
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                file_path: String::new(),
                                message: format!(
                                    "Modifying memory referenced by '{}' which holds return value from '{}()'. The return value should not be modified.",
                                    var_name, func_name
                                ),
                                line: start.row + 1,
                                column: start.column + 1,
                                severity: self.severity(),
                                suggestion: Some(
                                    "Copy the return value to a local buffer before modifying it"
                                        .to_string(),
                                ),
                                requires_manual_review: Some(false),
                            });
                        }
                    }
                }
            }

            // Check for calls that might modify protected variables
            if n.kind() == "call_expression" {
                self.check_call_for_modification(&n, source, protected_vars, violations);
            }
        }
    }

    fn check_call_for_modification(
        &self,
        node: &Node,
        source: &str,
        protected_vars: &HashMap<String, String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get function name
        let func_name = if let Some(func_node) = node.child_by_field_name("function") {
            get_node_text(&func_node, source).to_string()
        } else {
            return;
        };

        // Get argument list
        if let Some(args) = node.child_by_field_name("arguments") {
            let mut cursor = args.walk();
            let arg_list: Vec<_> = args
                .children(&mut cursor)
                .filter(|c| c.kind() != "(" && c.kind() != ")" && c.kind() != ",")
                .collect();

            // For modification functions, check ONLY the first argument (destination)
            // The second argument (source) is safe to be a protected variable
            if self.is_modification_function(&func_name) {
                if let Some(first_arg) = arg_list.first() {
                    if let Some((var_name, orig_func)) =
                        self.get_protected_var_ref(first_arg, source, protected_vars)
                    {
                        let start = node.start_position();
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            file_path: String::new(),
                            message: format!(
                                "Passing variable '{}' (from '{}()') as destination to modification function '{}()'.",
                                var_name, orig_func, func_name
                            ),
                            line: start.row + 1,
                            column: start.column + 1,
                            severity: self.severity(),
                            suggestion: Some(
                                "Copy the return value to a local buffer before passing as destination to modification functions"
                                    .to_string(),
                            ),
                            requires_manual_review: Some(false),
                        });
                    }
                }
            } else if !self.is_safe_function(&func_name)
                && !self.is_protected_function(&func_name)
                && !self.is_pointer_returning_function(&func_name)
            {
                // For unknown user-defined functions, check if a protected variable
                // is passed as the first argument (which could be modified)
                if let Some(first_arg) = arg_list.first() {
                    if let Some((var_name, orig_func)) =
                        self.get_protected_var_ref(first_arg, source, protected_vars)
                    {
                        let start = node.start_position();
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            file_path: String::new(),
                            message: format!(
                                "Passing variable '{}' (from '{}()') to function '{}()' which may modify it.",
                                var_name, orig_func, func_name
                            ),
                            line: start.row + 1,
                            column: start.column + 1,
                            severity: self.severity(),
                            suggestion: Some(
                                "Copy the return value to a local buffer before passing to functions that may modify it"
                                    .to_string(),
                            ),
                            requires_manual_review: Some(true),
                        });
                    }
                }
            }
        }
    }

    fn get_protected_var_ref(
        &self,
        node: &Node,
        source: &str,
        protected_vars: &HashMap<String, String>,
    ) -> Option<(String, String)> {
        match node.kind() {
            "identifier" => {
                let name = get_node_text(node, source);
                if let Some(func_name) = protected_vars.get(&scoped_key(node, name, source)) {
                    return Some((name.to_string(), func_name.clone()));
                }
            }
            "subscript_expression" => {
                // Check if the array base is a protected variable (e.g., env[0])
                if let Some(array) = node.child_by_field_name("argument") {
                    return self.get_protected_var_ref(&array, source, protected_vars);
                }
                // Also try first child for tree-sitter variations
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if let Some(result) = self.get_protected_var_ref(&child, source, protected_vars)
                    {
                        return Some(result);
                    }
                }
            }
            "pointer_expression" => {
                // Dereference: *ptr
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if let Some(result) = self.get_protected_var_ref(&child, source, protected_vars)
                    {
                        return Some(result);
                    }
                }
            }
            "field_expression" => {
                // Field access: conv->decimal_point
                if let Some(argument) = node.child_by_field_name("argument") {
                    return self.get_protected_var_ref(&argument, source, protected_vars);
                }
            }
            _ => {
                // Recurse into children for complex expressions
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if let Some(result) = self.get_protected_var_ref(&child, source, protected_vars)
                    {
                        return Some(result);
                    }
                }
            }
        }

        None
    }

    fn is_modification_function(&self, name: &str) -> bool {
        matches!(
            name,
            "strcpy"
                | "strncpy"
                | "strcat"
                | "strncat"
                | "sprintf"
                | "snprintf"
                // vsprintf/vsnprintf write to their first argument exactly
                // like sprintf/snprintf; must be classified here (checked
                // before is_safe_function below) so that folding
                // is_safe_function's printf sublist into
                // call_roles::is_printf_family doesn't newly treat them as
                // safe to pass a protected var to as a destination.
                | "vsprintf"
                | "vsnprintf"
                | "memcpy"
                | "memmove"
                | "memset"
                | "strtok"
                | "gets"
                | "fgets"
                // mktime NORMALISES the struct tm it is handed -- it writes
                // through its argument rather than reading it, so a tm from
                // gmtime()/localtime() passed here is modified in place. It
                // belongs with the writers even though it is not a copy-like
                // function: without it the call falls through to the
                // may-modify branch below, which reports the same line for a
                // weaker reason and marks it requires_manual_review
                // .
                | "mktime"
        )
    }

    fn is_safe_function(&self, name: &str) -> bool {
        // Pattern-based safe function detection for copy-like functions
        let name_lower = name.to_lowercase();
        if name_lower.contains("copy")
            || name_lower.contains("dup")
            || name_lower.contains("clone")
            || name_lower.ends_with("_safe")
            || name_lower.starts_with("safe_")
        {
            return true;
        }

        if call_roles::is_printf_family(name) {
            return true;
        }

        // Functions that don't modify their first argument (may read it but not write)
        matches!(
            name,
            // Output functions (read string, output elsewhere)
            "puts"
                | "fputs"
                | "fwrite"
                | "write"
                // String examination functions
                | "strlen"
                | "strcmp"
                | "strncmp"
                | "strchr"
                | "strrchr"
                | "strstr"
                | "strspn"
                | "strcspn"
                // String duplication (makes a copy, doesn't modify original)
                | "strdup"
                | "strndup"
                // Conversion functions (read string)
                | "atoi"
                | "atol"
                | "atof"
                | "strtol"
                | "strtoul"
                | "strtod"
                | "strtoll"
                | "strtoull"
                // Parsing/scanning
                | "sscanf"
                // Memory allocation
                | "free"
                | "malloc"
                | "calloc"
                | "realloc"
                // File operations (read path string)
                | "open"
                | "fopen"
                // dlopen belongs with them: its first parameter is
                // `const char *filename`, a path it reads and never writes.
                // Without it the call falls through to the unknown-function
                // branch, which reports "may modify it" about a pointer
                // dlopen provably does not touch -- lua's
                // `dlopen(rllib, RTLD_NOW | RTLD_LOCAL)` where rllib came
                // from getenv.
                | "dlopen"
                | "stat"
                | "lstat"
                | "access"
                | "unlink"
                | "remove"
                | "rename"
                | "mkdir"
                | "rmdir"
                | "chdir"
                | "opendir"
                // Logging/error handling
                | "perror"
                | "syslog"
                | "log_message"
                // Comparison and search
                | "memcmp"
                | "bsearch"
        )
    }

    fn is_protected_function(&self, name: &str) -> bool {
        matches!(
            name,
            "getenv"
                | "localeconv"
                | "setlocale"
                | "strerror"
                | "asctime"
                | "ctime"
                | "gmtime"
                | "localtime"
                | "getdate"
                | "getlogin"
        )
    }

    fn is_pointer_returning_function(&self, name: &str) -> bool {
        // Functions that return pointers into protected data but are not themselves protected
        matches!(name, "strchr" | "strrchr" | "strstr" | "strpbrk" | "memchr")
    }
}

/// The key a protected variable is recorded under: its name plus the start
/// of the declaration that binds this occurrence. Keyed by name alone, a
/// variable inherited the origin of every same-named variable in the
/// function: valkey acl.c's `sds errors = sdsempty();` was reported as
/// holding strerror()'s result because an unrelated `errors` in an earlier
/// block did (ADR-0006). A name that resolves to nothing in this file keys
/// by the name, as before.
fn scoped_key(ident: &Node, name: &str, source: &str) -> String {
    if ident.kind() != "identifier" {
        return name.to_string();
    }
    match resolve_identifier_declarator(ident, name, source) {
        Some((decl, _)) => declared_key(name, &decl),
        None => name.to_string(),
    }
}

/// [`scoped_key`] for a name at the declaration that introduces it.
fn declared_key(name: &str, declaration: &Node) -> String {
    format!("{}@{}", name, declaration.start_byte())
}

/// The values `node` stores: each `init_declarator`'s initializer for a
/// declaration, the right-hand side for an assignment.
fn stored_values<'t>(node: &Node<'t>) -> Vec<Node<'t>> {
    match node.kind() {
        "assignment_expression" => node.child_by_field_name("right").into_iter().collect(),
        "declaration" => {
            let mut cursor = node.walk();
            node.children(&mut cursor)
                .filter(|c| c.kind() == "init_declarator")
                .filter_map(|c| c.child_by_field_name("value"))
                .collect()
        }
        _ => Vec::new(),
    }
}

/// The calls whose RESULT is the stored value: the value itself, through
/// parentheses and casts, and either branch of a `?:`. Not a call nested in
/// an argument: `sdscatprintf(sdsempty(), "%s", strerror(errno))` returns a
/// new buffer that copied the text, and does not hand strerror()'s own
/// storage to its caller.
fn value_calls(value: Node) -> Vec<Node> {
    match value.kind() {
        "call_expression" => vec![value],
        "parenthesized_expression" => value.named_child(0).map(value_calls).unwrap_or_default(),
        "cast_expression" => value
            .child_by_field_name("value")
            .map(value_calls)
            .unwrap_or_default(),
        "conditional_expression" => ["consequence", "alternative"]
            .iter()
            .filter_map(|f| value.child_by_field_name(f))
            .flat_map(value_calls)
            .collect(),
        _ => Vec::new(),
    }
}
