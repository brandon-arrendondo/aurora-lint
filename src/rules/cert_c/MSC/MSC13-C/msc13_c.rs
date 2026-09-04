//! MSC13-C: Detect and remove unused values
//!
//! Detects local variables that are initialized or assigned but never
//! subsequently read. Dead stores waste computation and may indicate logic errors.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! void f() {
//!     int x = 42;  // VIOLATION: x is never used
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! void f() {
//!     int x = 42;
//!     printf("%d", x);  // x is used
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::{self as cfg_mod, FunctionCfg};
use crate::analyze::dataflow::{
    compute_reaching_definitions, extract_definitions, find_node_at_range, Definition,
    DefinitionKind,
};
use crate::analyze::macro_expand::{
    collect_function_macro_alternatives, macro_references_free_identifier, FunctionMacro,
};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{
    find_enclosing_declaration_for_identifier, get_identifier_from_declarator, get_node_text,
};
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Msc13C;

impl Msc13C {
    pub fn new() -> Self {
        Self
    }

    /// Collect all local variable declarations in a function body.
    /// Returns (name, declaration_line, has_initializer, decl_start_byte,
    /// enclosing_scope_start_byte). `decl_start_byte` is the byte offset of
    /// the specific `declaration` node that bound this name, so a later
    /// read can be checked against the exact declaration it resolves to
    /// rather than just its name — disambiguating same-named shadowing
    /// declarations in nested blocks (task 386). `enclosing_scope_start_byte`
    /// is the byte offset of the nearest real C scope (`compound_statement`/
    /// `for_statement`) containing the declaration, preprocessor-transparent
    /// like `find_enclosing_declaration_for_identifier`'s own scope search —
    /// used to group same-scope, same-name declarations split across
    /// mutually exclusive `#if`/`#elif`/`#else` branches (task 751).
    fn collect_local_vars(
        &self,
        body: &Node,
        source: &str,
    ) -> Vec<(String, usize, bool, usize, Option<usize>)> {
        let mut vars = Vec::new();
        self.walk_for_declarations(body, source, &mut vars);
        vars
    }

    /// Nearest enclosing C scope containing `node`, as its start byte.
    /// Preprocessor-transparent: walks past `preproc_if`/`preproc_elif`/
    /// `preproc_else` ancestors, the same way `find_enclosing_declaration_
    /// for_identifier`'s own scope search does, so two declarations of the
    /// same name in different branches of one `#if`/`#elif`/`#else` chain
    /// (or in separate but effectively mutually exclusive `#ifdef`/`#ifndef`
    /// pairs) resolve to the same scope rather than looking unrelated.
    fn enclosing_scope_start(node: &Node) -> Option<usize> {
        let mut cur = node.parent();
        while let Some(n) = cur {
            if matches!(n.kind(), "compound_statement" | "for_statement") {
                return Some(n.start_byte());
            }
            cur = n.parent();
        }
        None
    }

    /// Group declarations gathered by `collect_local_vars` that are
    /// mutually-exclusive preprocessor alternatives of one another: same
    /// enclosing scope, same name (task 751). C forbids two unconditional
    /// declarations of the same name in one scope, so any two same-scope,
    /// same-name declarations found here are necessarily each guarded by
    /// some combination of `#if`/`#ifdef`/`#elif`/`#else`/`#ifndef` that
    /// only ever compiles one of them — they should be treated as one
    /// liveness entity, so a read resolving to any one of them counts as a
    /// read of all of them. Returns a map from each declaration's own
    /// `decl_start_byte` to the full list of `decl_start_byte`s in its
    /// group (a singleton list when the declaration has no alternatives).
    fn build_decl_start_to_group(
        &self,
        local_vars: &[(String, usize, bool, usize, Option<usize>)],
    ) -> HashMap<usize, Vec<usize>> {
        let mut by_key: HashMap<(Option<usize>, &str), Vec<usize>> = HashMap::new();
        for (name, _, _, decl_start, scope_start) in local_vars {
            by_key
                .entry((*scope_start, name.as_str()))
                .or_default()
                .push(*decl_start);
        }
        let mut out = HashMap::new();
        for group in by_key.into_values() {
            for &d in &group {
                out.insert(d, group.clone());
            }
        }
        out
    }

    /// Names of variables whose reaching-definitions liveness can be judged
    /// from a single call: declared locally in this function body, and NOT
    /// `static`. A `static` local's lifetime (and its read-set -- classic
    /// ring-buffer-average or lazy-init-guard idioms read the value written
    /// on the *previous* call, at the top of this one) spans every call, so
    /// per-invocation reaching-definitions is the wrong tool for it: a write
    /// with no read before this call returns isn't dead, it's read on the
    /// next call. A name that isn't declared in this body at all (a
    /// file-scope global or another function's `static`) has the same
    /// problem for the same reason. Both are excluded from dead-store
    /// checking entirely by simply never appearing in this set.
    fn collect_single_invocation_locals(&self, body: &Node, source: &str) -> HashSet<String> {
        let mut names = HashSet::new();
        self.walk_for_single_invocation_locals(body, source, &mut names);
        names
    }

    fn walk_for_single_invocation_locals(
        &self,
        node: &Node,
        source: &str,
        names: &mut HashSet<String>,
    ) {
        if node.kind() == "declaration" {
            let decl_text = get_node_text(node, source);
            let is_static = (0..node.child_count()).any(|i| {
                node.child(i).is_some_and(|c| {
                    c.kind() == "storage_class_specifier" && get_node_text(&c, source) == "static"
                })
            });
            // See walk_for_declarations: a declaration with a genuine parse
            // error (e.g. embedded JS inside EM_ASM) can't be trusted to
            // name a real variable.
            if !decl_text.contains("extern ")
                && !decl_text.contains("typedef ")
                && !is_static
                && !node.has_error()
            {
                let mut vars = Vec::new();
                let decl_start = node.start_byte();
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        self.extract_declared_names(&child, source, decl_start, None, &mut vars);
                    }
                }
                names.extend(vars.into_iter().map(|(name, _, _, _, _)| name));
            }
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() != "function_definition" {
                    self.walk_for_single_invocation_locals(&child, source, names);
                }
            }
        }
    }

    fn walk_for_declarations(
        &self,
        node: &Node,
        source: &str,
        vars: &mut Vec<(String, usize, bool, usize, Option<usize>)>,
    ) {
        if node.kind() == "declaration" {
            // Skip function declarations and extern/typedef
            let decl_text = get_node_text(node, source);
            // A declaration containing a genuine parse error can't be
            // trusted to name a real variable at all. This is how
            // Emscripten's `EM_ASM({ const width = $0; ... })` embeds raw
            // JavaScript inside C: tree-sitter-c treats `width` as a
            // type_identifier and recovers `$0` as a bare `identifier`
            // inside an ERROR node, which this pass would otherwise flag
            // as a phantom "declared but never used" variable named `$0`
            // (task 444). Name-independent by design -- any macro that
            // embeds non-C content the same way hits the same guard.
            if decl_text.contains("extern ") || decl_text.contains("typedef ") || node.has_error() {
                // Don't flag extern/typedef declarations or malformed parses
            } else {
                let decl_start = node.start_byte();
                let scope_start = Self::enclosing_scope_start(node);
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        self.extract_declared_names(&child, source, decl_start, scope_start, vars);
                    }
                }
            }
        }

        // Recurse into children (but not into nested function definitions)
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() != "function_definition" {
                    self.walk_for_declarations(&child, source, vars);
                }
            }
        }
    }

    fn extract_declared_names(
        &self,
        node: &Node,
        source: &str,
        decl_start: usize,
        scope_start: Option<usize>,
        vars: &mut Vec<(String, usize, bool, usize, Option<usize>)>,
    ) {
        match node.kind() {
            "init_declarator" => {
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    let name = get_identifier_from_declarator(&declarator, source);
                    if !name.is_empty() {
                        vars.push((
                            name,
                            node.start_position().row + 1,
                            true,
                            decl_start,
                            scope_start,
                        ));
                    }
                }
            }
            // Plain identifier declaration: `int x;`
            "identifier" => {
                let name = get_node_text(node, source).to_string();
                vars.push((
                    name,
                    node.start_position().row + 1,
                    false,
                    decl_start,
                    scope_start,
                ));
            }
            // Pointer/array declarator without init: `int *p;`, `int arr[10];`
            "pointer_declarator" | "array_declarator" => {
                let name = get_identifier_from_declarator(node, source);
                if !name.is_empty() {
                    vars.push((
                        name,
                        node.start_position().row + 1,
                        false,
                        decl_start,
                        scope_start,
                    ));
                }
            }
            // Skip function_declarator (function declarations, not variables)
            "function_declarator" => {}
            _ => {}
        }
    }

    /// Count how many times a variable name appears as a "read" reference in
    /// the function body. A "read" is any identifier reference that is NOT:
    /// - The left side of an assignment expression
    /// - The declarator in a declaration
    /// - The operand of address-of (&) used as an out-parameter
    ///
    /// `decl_starts`, when given, are the byte offset(s) of the specific
    /// declaration(s) this count is for; an occurrence is only counted when
    /// it actually resolves (via `find_enclosing_declaration_for_identifier`)
    /// to one of those declarations, not a same-named shadowing declaration
    /// in a nested or sibling block (task 386). More than one byte offset
    /// means the declarations are mutually-exclusive preprocessor
    /// alternatives of one another treated as a single liveness entity
    /// (task 751) -- a read resolving to any of them counts as a read of
    /// all of them. `None` falls back to unscoped name matching, for
    /// callers that can't resolve a specific declaration.
    fn count_reads(
        &self,
        body: &Node,
        source: &str,
        var_name: &str,
        decl_starts: Option<&[usize]>,
    ) -> usize {
        let mut count = 0;
        self.walk_for_reads(body, source, var_name, decl_starts, &mut count);
        count
    }

    fn walk_for_reads(
        &self,
        node: &Node,
        source: &str,
        var_name: &str,
        decl_starts: Option<&[usize]>,
        count: &mut usize,
    ) {
        if node.kind() == "identifier" {
            let text = get_node_text(node, source);
            if text == var_name && self.is_read_context(node, source) {
                let in_scope = match decl_starts {
                    None => true,
                    Some(targets) => {
                        find_enclosing_declaration_for_identifier(node, var_name, source)
                            .is_some_and(|d| targets.contains(&d.start_byte()))
                    }
                };
                if in_scope {
                    *count += 1;
                }
            }
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                // Don't recurse into nested function definitions
                if child.kind() != "function_definition" {
                    self.walk_for_reads(&child, source, var_name, decl_starts, count);
                }
            }
        }
    }

    /// True if some function-like macro invoked inside `body` has a
    /// replacement list that names `var_name` as a free identifier — in
    /// which case the variable IS used, in text sqc's identifier walk never
    /// sees, because the name does not appear at the call site at all.
    ///
    /// sqlite's `src/complete.c` is the worked example. `unsigned char c;`
    /// is declared under `#ifdef SQLITE_EBCDIC` and looks plainly unused
    /// until you find the `IdChar` definition under the same guard —
    /// `#define IdChar(C)  (((c=C)>=0x42 && sqlite3IsEbcdicIdChar[c-0x40]))`
    /// — whose body both writes and reads `c`, and which is called twice in
    /// the declaring block.
    ///
    /// Every preprocessor alternative of a macro name is consulted, not just
    /// the first (see `collect_function_macro_alternatives`): the definition
    /// that explains the declaration is normally the one under the same
    /// `#ifdef`, and which of the two the expander would have picked is
    /// irrelevant to whether a use exists.
    ///
    /// Scoped to macros defined in this file. A macro defined in a header
    /// is not visible here, so the same shape across a `#include` still
    /// reports — under-suppression, which is the safe direction.
    fn macro_hides_use(
        &self,
        body: &Node,
        source: &str,
        macros: &HashMap<String, Vec<FunctionMacro>>,
        var_name: &str,
    ) -> bool {
        if macros.is_empty() {
            return false;
        }
        let mut invoked = HashSet::new();
        self.collect_invoked_names(body, source, &mut invoked);
        invoked.iter().any(|name| {
            macros.get(name.as_str()).is_some_and(|alts| {
                alts.iter()
                    .any(|m| macro_references_free_identifier(m, var_name))
            })
        })
    }

    /// Names of every callee invoked in `node`'s subtree, whether it is a
    /// real function or a function-like macro — syntactically identical, and
    /// the caller resolves which by lookup.
    fn collect_invoked_names(&self, node: &Node, source: &str, out: &mut HashSet<String>) {
        if node.kind() == "call_expression" {
            if let Some(f) = node.child_by_field_name("function") {
                if f.kind() == "identifier" {
                    out.insert(get_node_text(&f, source).to_string());
                }
            }
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() != "function_definition" {
                    self.collect_invoked_names(&child, source, out);
                }
            }
        }
    }

    /// Determines if an identifier is in a "read" context (its value is consumed).
    fn is_read_context(&self, node: &Node, source: &str) -> bool {
        let parent = match node.parent() {
            Some(p) => p,
            None => return true,
        };

        match parent.kind() {
            // Assignment expression — check if simple (=) or compound (+=, -=, etc.)
            "assignment_expression" => {
                if let Some(left) = parent.child_by_field_name("left") {
                    if left.id() == node.id() {
                        // Compound assignment LHS (+=, -=, *=, etc.) is both read and write
                        if let Some(op) = parent.child_by_field_name("operator") {
                            let op_text = get_node_text(&op, source);
                            if op_text != "=" {
                                return true; // compound: LHS is read
                            }
                        }
                        return false; // simple =: LHS is pure write
                    }
                }
                true
            }
            // Init declarator: `type name = value;`. The declarator name is
            // the declaration itself (not a read), but the initializer VALUE
            // — when it's a bare identifier, e.g. `int y = x;` — is a read of
            // that identifier's prior value.
            "init_declarator" => parent
                .child_by_field_name("value")
                .is_some_and(|value| value.id() == node.id()),
            // Declaration — not a read
            "declaration" => false,
            // Pointer declarator, array declarator in a declaration — not a read
            "pointer_declarator" | "array_declarator" => {
                // Check if we're inside a declaration
                let mut p = parent.parent();
                while let Some(pp) = p {
                    if pp.kind() == "declaration" {
                        return false;
                    }
                    if pp.kind() == "function_definition" || pp.kind() == "compound_statement" {
                        break;
                    }
                    p = pp.parent();
                }
                true
            }
            // Field expression: data.field / data->field. Even when this
            // whole field_expression is an assignment's LHS (`data.field =
            // value`), the base `data` identifier is still read — its
            // pointer/struct value is needed to locate the field being
            // written. Only the field name itself (a field_identifier, not
            // an identifier, so never reaches this function) is a pure write.
            "field_expression" => true,
            // Subscript expression: data[i] = value still reads both the
            // base pointer `data` (needed to compute the write address) and
            // the index `i` — neither is a pure write target.
            "subscript_expression" => true,
            // Update expression (x++, ++x) — this is a read+write
            "update_expression" => true,
            // Address-of in a call argument: func(&x) — treat as read
            // because the function may read through the pointer
            "unary_expression" => {
                if let Some(op) = parent.child_by_field_name("operator") {
                    let op_text = get_node_text(&op, source);
                    if op_text == "&" {
                        return true; // &x — function may read
                    }
                }
                true
            }
            _ => true,
        }
    }
}

impl CertRule for Msc13C {
    fn rule_id(&self) -> &'static str {
        "MSC13-C"
    }

    fn description(&self) -> &'static str {
        "Detect and remove unused values"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "MSC13-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Every preprocessor branch's definition of every function-like
        // macro in this file, for the macro-hidden-use check below. Built
        // once per file, not per function.
        let macros = collect_function_macro_alternatives(source);

        // Walk all function definitions
        self.check_functions(node, source, &macros, &mut violations);

        violations
    }
}

impl Msc13C {
    fn check_functions(
        &self,
        node: &Node,
        source: &str,
        macros: &HashMap<String, Vec<FunctionMacro>>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() == "function_definition" {
            if let Some(body) = node.child_by_field_name("body") {
                self.check_function_body(node, &body, source, macros, violations);
            }
        }

        // Recurse into preproc blocks and other containers
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() != "function_definition"
                    || node.kind() == "translation_unit"
                    || node.kind().starts_with("preproc_")
                {
                    self.check_functions(&child, source, macros, violations);
                }
            }
        }
    }

    fn check_function_body(
        &self,
        func_node: &Node,
        body: &Node,
        source: &str,
        macros: &HashMap<String, Vec<FunctionMacro>>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Collect all local variable declarations
        let local_vars = self.collect_local_vars(body, source);
        // Same-scope, same-name declarations split across mutually
        // exclusive `#if`/`#elif`/`#else` branches are one liveness entity
        // (task 751): group them so a read resolving to any one of them
        // counts as a read of all of them.
        let decl_groups = self.build_decl_start_to_group(&local_vars);

        // Check each declared variable for reads
        for (name, line, has_init, decl_start, _scope_start) in &local_vars {
            let targets = decl_groups
                .get(decl_start)
                .cloned()
                .unwrap_or_else(|| vec![*decl_start]);
            let reads = self.count_reads(body, source, name, Some(&targets));
            if reads == 0 && !self.macro_hides_use(body, source, macros, name) {
                let msg = if *has_init {
                    format!("Variable '{}' is initialized but never read.", name)
                } else {
                    format!("Variable '{}' is declared but never used.", name)
                };
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: msg,
                    file_path: String::new(),
                    line: *line,
                    column: 1,
                    suggestion: Some("Use the variable or remove it".to_string()),
                    ..Default::default()
                });
            }
        }

        // Dead store detection: an assignment whose value never reaches a
        // read on any executable path before being overwritten or the
        // function exiting.
        self.check_dead_stores(func_node, &decl_groups, body, source, violations);
    }

    /// Detect dead stores using the real CFG + reaching-definitions
    /// analysis (`src/analyze/dataflow.rs`), falling back to the
    /// conservative straight-line sibling scan only when a CFG can't be
    /// built for this function (e.g. malformed body).
    ///
    /// Per-definition liveness: for each write, does ITS specific value
    /// reach any read before being killed by a later write on that path,
    /// or the function returning? A name-based "is the variable read
    /// again anywhere later" check (as used by the unused-variable pass
    /// above) is unsound for this — e.g. CERT's own canonical example:
    ///
    /// ```c
    /// p1 = foo();
    /// p2 = bar();          // dead: bar()'s result is never read on any path
    /// if (baz()) {
    ///     return p1;        // p2 never touched, never read
    /// } else {
    ///     p2 = p1;          // p2 overwritten before any read
    /// }
    /// return p2;            // only ever reads the p1-derived value
    /// ```
    ///
    /// `p2` IS referenced again later, so a name-based check calls it
    /// "used" — but bar()'s specific definition is dead on every path.
    fn check_dead_stores(
        &self,
        func_node: &Node,
        decl_groups: &HashMap<usize, Vec<usize>>,
        body: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        match cfg_mod::build_function_cfg(func_node, source) {
            Some(cfg) => {
                self.check_dead_stores_cfg(func_node, &cfg, decl_groups, body, source, violations)
            }
            None => self.check_dead_stores_in_blocks(body, source, violations),
        }
    }

    /// Per-definition liveness via reaching-definitions. For every write
    /// (declaration-with-initializer or simple `=` assignment) inside the
    /// function body, walk each CFG block's statements in source order,
    /// tracking which definition of each variable is currently "active"
    /// at that point in the block. A read marks the currently active
    /// definition live — resolved locally if this block already wrote the
    /// variable, otherwise via the block's `reaching_in` set (which
    /// correctly folds in predecessor blocks across branches, loops, and
    /// goto edges, because it's derived from the actual CFG rather than a
    /// text heuristic). Any write whose definition is never marked live is
    /// a dead store.
    fn check_dead_stores_cfg(
        &self,
        func_node: &Node,
        cfg: &FunctionCfg,
        decl_groups: &HashMap<usize, Vec<usize>>,
        body: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let definitions = extract_definitions(cfg, func_node, source);
        let reaching = compute_reaching_definitions(cfg, definitions);
        let single_invocation_locals = self.collect_single_invocation_locals(body, source);

        // (block_id, statement_index) -> definition indices written there.
        let mut writes_at: HashMap<(usize, usize), Vec<usize>> = HashMap::new();
        for (idx, def) in reaching.definitions.iter().enumerate() {
            writes_at
                .entry((def.block_id, def.statement_index))
                .or_default()
                .push(idx);
        }

        let mut live: HashSet<usize> = HashSet::new();

        for block in &cfg.blocks {
            let mut active: HashMap<String, usize> = HashMap::new();
            for (stmt_idx, &(start, end)) in block.statements.iter().enumerate() {
                let Some(stmt_node) = find_node_at_range(body, start, end) else {
                    continue;
                };

                let mut reads = HashSet::new();
                self.collect_reads_in_node(&stmt_node, source, &mut reads);
                for var in &reads {
                    if let Some(&def_idx) = active.get(var) {
                        live.insert(def_idx);
                    } else if let Some(in_set) = reaching.reaching_in.get(&block.id) {
                        for &idx in in_set {
                            if &reaching.definitions[idx].variable == var {
                                live.insert(idx);
                            }
                        }
                    }
                }

                if let Some(idxs) = writes_at.get(&(block.id, stmt_idx)) {
                    for &idx in idxs {
                        active.insert(reaching.definitions[idx].variable.clone(), idx);
                    }
                }
            }
        }

        for (idx, def) in reaching.definitions.iter().enumerate() {
            if live.contains(&idx) {
                continue;
            }
            // `extract_definitions` also emits a synthetic `FreeCall`
            // pseudo-definition at every `free(var)` call site, for the
            // null/use-after-free tracking MEM30-C/MEM31-C need. It isn't a
            // value-producing write at all -- there's nothing for a later
            // statement to "read" back -- so treating it like a real
            // definition made MSC13-C flag the *previous* genuine
            // assignment as a dead store whenever its only reads happened
            // before the variable was freed (task 391: hostap's rfkill.c
            // `found = os_strcmp(phy, rfk_phy) == 0; free(rfk_phy);` --
            // `rfk_phy`'s real read is the `os_strcmp` call, but the
            // `free()` pseudo-definition right after it had no read of its
            // own and got reported instead).
            if def.kind == DefinitionKind::FreeCall {
                continue;
            }
            // Parameters live in the function declarator, before the body
            // — unused parameters are out of scope for this rule.
            if def.byte_offset < body.start_byte() {
                continue;
            }
            // `static` locals and file-scope globals have a lifetime and
            // read-set spanning every call, not just this one — a write with
            // no read on THIS invocation's paths may still be read at the
            // top of the NEXT call (ring-buffer/lazy-init idioms). This
            // per-call reaching-definitions analysis can't see across calls,
            // so it isn't the right tool for either; skip them entirely.
            if !single_invocation_locals.contains(&def.variable) {
                continue;
            }
            // A variable never read anywhere in the function is already
            // reported by the unused-variable pass above; don't
            // double-report the same root cause per definition. Scoped to
            // this definition's own governing declaration (task 386) so a
            // read of an unrelated same-named shadowing variable elsewhere
            // in the function doesn't suppress this report.
            let decl_start = self.declaration_scope_for_definition(cfg, def, body, source);
            let targets =
                decl_start.map(|d| decl_groups.get(&d).cloned().unwrap_or_else(|| vec![d]));
            if self.count_reads(body, source, &def.variable, targets.as_deref()) == 0 {
                continue;
            }
            let line = Self::line_for_byte(source, def.byte_offset);
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                message: format!(
                    "Value assigned to '{}' is never read on any execution path before being overwritten or the function returning.",
                    def.variable
                ),
                file_path: String::new(),
                line,
                column: 1,
                suggestion: Some(
                    "Remove the dead assignment or use its value before it is overwritten"
                        .to_string(),
                ),
                ..Default::default()
            });
        }
    }

    /// Resolve the specific local declaration governing `def`'s write, for
    /// shadow-aware read counting (task 386): locate the definition's own
    /// statement via its CFG block/index, find the identifier occurrence
    /// naming `def.variable` within it, then walk up to the nearest
    /// enclosing declaration that binds that name. Returns `None` when it
    /// can't be resolved, in which case the caller falls back to unscoped
    /// name matching.
    fn declaration_scope_for_definition(
        &self,
        cfg: &FunctionCfg,
        def: &Definition,
        body: &Node,
        source: &str,
    ) -> Option<usize> {
        let &(start, end) = cfg
            .blocks
            .get(def.block_id)?
            .statements
            .get(def.statement_index)?;
        let stmt_node = find_node_at_range(body, start, end)?;
        let ident = query::find_first_descendant(stmt_node, |n| {
            n.kind() == "identifier" && get_node_text(&n, source) == def.variable
        })?;
        find_enclosing_declaration_for_identifier(&ident, &def.variable, source)
            .map(|d| d.start_byte())
    }

    fn line_for_byte(source: &str, byte_offset: usize) -> usize {
        source.as_bytes()[..byte_offset.min(source.len())]
            .iter()
            .filter(|&&b| b == b'\n')
            .count()
            + 1
    }

    /// Collect the set of variable names read anywhere in `node`'s
    /// subtree, reusing `is_read_context` to exclude pure write targets
    /// (declaration names, simple-assignment LHS, etc.).
    fn collect_reads_in_node(&self, node: &Node, source: &str, out: &mut HashSet<String>) {
        if node.kind() == "identifier" && self.is_read_context(node, source) {
            out.insert(get_node_text(node, source).to_string());
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() != "function_definition" {
                    self.collect_reads_in_node(&child, source, out);
                }
            }
        }
    }

    /// Recurse to every compound_statement (function body, if/loop/switch
    /// bodies, bare nested blocks) and run the direct-sibling dead-store
    /// scan on each independently.
    fn check_dead_stores_in_blocks(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() == "compound_statement" {
            self.scan_block_direct_children(node, source, violations);
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() != "function_definition" {
                    self.check_dead_stores_in_blocks(&child, source, violations);
                }
            }
        }
    }

    /// Extract every `(name, line)` write if `stmt` is a simple (`=`, not
    /// compound) assignment or an initialized declaration (possibly with
    /// multiple comma-separated declarators, e.g. `char *a = NULL, *b = NULL;`),
    /// at this statement's top level.
    fn simple_writes(&self, stmt: &Node, source: &str) -> Vec<(String, usize)> {
        match stmt.kind() {
            "expression_statement" => {
                let Some(expr) = stmt.child(0) else {
                    return Vec::new();
                };
                if expr.kind() != "assignment_expression" {
                    return Vec::new();
                }
                let is_simple = expr
                    .child_by_field_name("operator")
                    .is_none_or(|op| get_node_text(&op, source) == "=");
                if !is_simple {
                    return Vec::new();
                }
                let Some(left) = expr.child_by_field_name("left") else {
                    return Vec::new();
                };
                if left.kind() != "identifier" {
                    return Vec::new();
                }
                vec![(
                    get_node_text(&left, source).to_string(),
                    stmt.start_position().row + 1,
                )]
            }
            "declaration" => {
                let line = stmt.start_position().row + 1;
                let mut writes = Vec::new();
                for i in 0..stmt.child_count() {
                    if let Some(c) = stmt.child(i) {
                        if c.kind() == "init_declarator" {
                            if let Some(declarator) = c.child_by_field_name("declarator") {
                                let name = get_identifier_from_declarator(&declarator, source);
                                if !name.is_empty() {
                                    writes.push((name, line));
                                }
                            }
                        }
                    }
                }
                writes
            }
            _ => Vec::new(),
        }
    }

    /// Scan the direct (top-level) statement children of one block in
    /// source order, pairing a write with an immediately-following
    /// same-block write to the same variable when nothing between them
    /// reads it — and treating any other statement kind (branch, loop,
    /// switch, label, goto, bare nested block, return, ...) as a boundary:
    /// if it mentions the pending variable at all, stop tracking it rather
    /// than risk a false pair across control flow we don't model here.
    fn scan_block_direct_children(
        &self,
        block: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let mut pending: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        for i in 0..block.child_count() {
            let Some(stmt) = block.child(i) else { continue };
            if matches!(stmt.kind(), "{" | "}") {
                continue;
            }

            let writes = self.simple_writes(&stmt, source);
            if !writes.is_empty() {
                let written_names: std::collections::HashSet<&str> =
                    writes.iter().map(|(n, _)| n.as_str()).collect();
                // Any OTHER pending var mentioned anywhere in this statement
                // (e.g. on an initializer's RHS) is now read.
                for other in pending.keys().cloned().collect::<Vec<_>>() {
                    if !written_names.contains(other.as_str())
                        && self.mentions_identifier(&stmt, source, &other)
                    {
                        pending.remove(&other);
                    }
                }
                for (name, line) in writes {
                    if let Some(&prev_line) = pending.get(&name) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            message: format!(
                                "Value assigned to '{}' is overwritten before being read.",
                                name
                            ),
                            file_path: String::new(),
                            line: prev_line,
                            column: 1,
                            suggestion: Some(
                                "Remove the dead assignment or use its value before reassigning"
                                    .to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                    pending.insert(name, line);
                }
                continue;
            }

            // A goto or label, anywhere in this statement's subtree (not
            // just at its top level — e.g. `if (err) { ...; goto out; }`),
            // means control can jump past "the next same-block write" to
            // reach code where the value we're tracking is still read (a
            // shared cleanup label). Drop everything pending rather than
            // risk pairing across a jump we can't see the target of.
            if matches!(stmt.kind(), "goto_statement" | "labeled_statement")
                || self.contains_goto_or_label(&stmt)
            {
                pending.clear();
                continue;
            }

            // Not a recognized simple write: a boundary. Clear any pending
            // var this statement mentions at all (read or write) rather
            // than reason about its internal control flow.
            for name in pending.keys().cloned().collect::<Vec<_>>() {
                if self.mentions_identifier(&stmt, source, &name) {
                    pending.remove(&name);
                }
            }
        }
    }

    /// Whether `goto`/a label appears anywhere in this subtree.
    fn contains_goto_or_label(&self, node: &Node) -> bool {
        if matches!(node.kind(), "goto_statement" | "labeled_statement") {
            return true;
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() != "function_definition" && self.contains_goto_or_label(&child) {
                    return true;
                }
            }
        }
        false
    }

    /// Whether `var_name` appears anywhere in this subtree (as any kind of
    /// identifier reference), regardless of read/write context.
    fn mentions_identifier(&self, node: &Node, source: &str, var_name: &str) -> bool {
        if node.kind() == "identifier" && get_node_text(node, source) == var_name {
            return true;
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() != "function_definition"
                    && self.mentions_identifier(&child, source, var_name)
                {
                    return true;
                }
            }
        }
        false
    }
}
