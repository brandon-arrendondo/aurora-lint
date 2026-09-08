use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::analyze::function_summary::{self, FunctionSummary};
use crate::analyze::macro_expand::{self, FunctionMacro};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use crate::utility::cert_c::call_roles;
use crate::utility::cert_c::declarator_utils;
use crate::utility::cert_c::overflow_helpers;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// Reduce a call argument to the variable it names, reporting whether it was
/// named by address.
///
/// `p` yields `(p, false)`; `&p` and `(void **)&p` yield `(p, true)`.
/// Parentheses and casts are transparent. Anything else — a field, a
/// subscript, a nested call — yields `None`.
fn strip_call_argument(arg: Node) -> Option<(Node, bool)> {
    fn peel(mut n: Node) -> Node {
        loop {
            let inner = match n.kind() {
                "parenthesized_expression" => n.named_child(0),
                "cast_expression" => n.child_by_field_name("value"),
                _ => None,
            };
            match inner {
                Some(i) => n = i,
                None => return n,
            }
        }
    }

    let node = peel(arg);
    if node.kind() == "identifier" {
        return Some((node, false));
    }
    if node.kind() == "pointer_expression" {
        let op = node.child_by_field_name("operator")?;
        if op.kind() != "&" {
            return None;
        }
        let inner = peel(node.child_by_field_name("argument")?);
        if inner.kind() == "identifier" {
            return Some((inner, true));
        }
    }
    None
}

pub struct Mem31C {
    function_summaries: RefCell<HashMap<String, FunctionSummary>>,
    value_only_globals: RefCell<HashSet<String>>,
    struct_field_types: RefCell<HashMap<String, HashMap<String, String>>>,
    struct_typedef_aliases: RefCell<HashMap<String, String>>,
    known_functions: RefCell<HashSet<String>>,
    function_macros: RefCell<HashMap<String, FunctionMacro>>,
    /// Cross-file noreturn function names from the prescan, unioned in
    /// `check` with the ones this file declares for itself (task 1076).
    noreturn_functions: RefCell<HashSet<String>>,
}

impl Mem31C {
    pub fn new() -> Self {
        Self {
            function_summaries: RefCell::new(HashMap::new()),
            value_only_globals: RefCell::new(HashSet::new()),
            struct_field_types: RefCell::new(HashMap::new()),
            struct_typedef_aliases: RefCell::new(HashMap::new()),
            known_functions: RefCell::new(HashSet::new()),
            function_macros: RefCell::new(HashMap::new()),
            noreturn_functions: RefCell::new(HashSet::new()),
        }
    }
}

impl CertRule for Mem31C {
    fn rule_id(&self) -> &'static str {
        "MEM31-C"
    }

    fn description(&self) -> &'static str {
        "Free dynamically allocated memory when no longer needed"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "MEM31-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();
        *self.value_only_globals.borrow_mut() = context.value_only_globals.clone();
        *self.struct_field_types.borrow_mut() = context.struct_field_types.clone();
        *self.struct_typedef_aliases.borrow_mut() = context.struct_typedef_aliases.clone();
        *self.known_functions.borrow_mut() = context.known_functions.clone();
        *self.function_macros.borrow_mut() = context.function_macros.clone();
        *self.noreturn_functions.borrow_mut() = context.noreturn_functions.clone();
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let summaries = self.function_summaries.borrow();
        let value_only_globals = self.value_only_globals.borrow();
        let struct_field_types = self.struct_field_types.borrow();
        let struct_typedef_aliases = self.struct_typedef_aliases.borrow();
        let known_functions = self.known_functions.borrow();
        let function_macros = self.function_macros.borrow();

        // A call that never returns ends its branch exactly as `return` does.
        // The prescan set carries declarations from headers this parse never
        // sees; the per-file pass catches a helper declared only here.
        let mut noreturn_names = self.noreturn_functions.borrow().clone();
        noreturn_names.extend(crate::analyze::noreturn::collect_noreturn_function_names(
            node, source,
        ));

        // Analyze each function independently for memory leaks
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            let mut analyzer = MemoryLeakAnalyzer::new(
                &summaries,
                &value_only_globals,
                &struct_field_types,
                &struct_typedef_aliases,
                &known_functions,
                &function_macros,
                &noreturn_names,
            );
            analyzer.analyze_function(&func, source, &mut violations);
        }

        violations
    }
}

struct MemoryLeakAnalyzer<'a> {
    // Track allocated memory by variable name
    allocated_memory: HashMap<String, AllocInfo>,
    // Track freed memory: var_name -> (line, column) of free call
    freed_memory: HashMap<String, (usize, usize)>,
    // Track variables that are returned or stored globally
    escaped_memory: HashSet<String>,
    // Track variables known to be NULL in current scope (from NULL checks)
    null_variables: HashSet<String>,
    // Collect double-free violations during analysis
    double_free_violations: Vec<RuleViolation>,
    // Collect leak violations found at early returns
    leak_violations: Vec<RuleViolation>,
    // Track if we're inside a loop (for double-free detection)
    in_loop: bool,
    // Track loop nesting depth for proper double-free detection
    loop_depth: usize,
    // Track what variables are freed at each label (for goto analysis)
    label_frees: HashMap<String, HashSet<String>>,
    // The freed-pointer state each goto-reachable label is actually entered
    // with: `freed_memory` snapshotted at every visited `goto L`, intersected
    // across all of them. See `visit_labeled_statement`.
    goto_freed_states: HashMap<String, HashMap<String, (usize, usize)>>,
    // Frees dropped from `freed_memory` on entry to a goto-only label,
    // re-credited by the end-of-function leak sweep. See
    // `visit_labeled_statement`.
    discarded_label_frees: HashMap<String, (usize, usize)>,
    // Track realloc relationships: result_var -> old_ptr
    realloc_relations: HashMap<String, String>,
    // Track if signal() has been called in this function
    signal_registered: bool,
    // Track loop allocation/free patterns: array_base -> (alloc_condition, free_condition)
    loop_array_patterns: HashMap<String, (Option<String>, Option<String>)>,
    // Function summaries from prescan for inter-procedural analysis
    function_summaries: &'a HashMap<String, FunctionSummary>,
    // Names of this function's own parameters (task 306: a struct reached
    // through a bare parameter is caller-owned/borrowed — this function
    // populating one of its fields doesn't make this function responsible
    // for freeing it at return).
    function_params: HashSet<String>,
    // Parameters whose *pointee* was freshly allocated in this function via
    // a `*param = malloc(...)`-shaped out-parameter assignment. A struct
    // reached this way (e.g. `(*out)->field = malloc(...)`) IS this
    // function's own fresh allocation, not a borrowed caller struct, so it
    // stays a leak candidate.
    deref_allocated_params: HashSet<String>,
    // Local variables declared `static` (function-static storage
    // duration): CERT's own MEM31-C-EX2 exempts memory that's kept alive
    // for the remaining lifetime of the program, and a function-static
    // pointer used as a lazily-initialized cache (allocate once, reuse
    // across calls, never freed) is exactly that pattern -- not a leak
    // just because the function returns without freeing it.
    static_variables: HashSet<String>,
    // Locals declared with a non-pointer, non-array declarator that are
    // never used in a pointer-shaped way anywhere in the body (no `->`,
    // no unary `*`, no subscript, no NULL comparison). Nothing that holds
    // heap memory can look like this, so a `*_new`-style *name-heuristic*
    // allocation stored into one of them is not an allocation at all
    // (task 580).
    value_only_locals: HashSet<String>,
    // Project-wide value-only globals (`ProjectContext::value_only_globals`,
    // task 652): the cross-file counterpart of `value_only_locals` for a
    // name-heuristic allocation stored straight into a genuine global/extern
    // variable with no local declaration in this function at all (e.g.
    // seL4's `current_lookup_fault = lookup_fault_new(...)`, assigned from
    // several translation units, declared only via `extern` in a header).
    value_only_globals: &'a HashSet<String>,
    // Struct-field assignment targets whose DECLARED FIELD TYPE is positively
    // a non-pointer (task: MEM31-C `*_new` return-type FP). The third target
    // shape `value_only_locals`/`value_only_globals` do not reach: the guard
    // those two apply is about the ROOT variable's declared shape, and for
    // `callerSlot->cap = cap_null_cap_new()` the root is a perfectly real
    // `cte_t *`, so neither set ever matches and the name-shape guess stands
    // unchallenged. What settles it is the field's own type -- `struct cte`
    // declares `cap_t cap;`, a struct held by value, so nothing stored there
    // can be heap memory to begin with.
    value_only_fields: HashSet<String>,
    // Project-wide `struct_name -> field_name -> type_text`, used to resolve
    // the above. Cross-file by necessity: seL4 declares `struct cte` in
    // `include/object/structures.h` and assigns its field in
    // `src/fastpath/fastpath.c`.
    struct_field_types: &'a HashMap<String, HashMap<String, String>>,
    // `Alias -> Tag` for every `typedef struct Tag Alias;`
    // (`ProjectContext::struct_typedef_aliases`, task 963). Required, not
    // optional: seL4 spells all three of the structs this guard needs as a
    // BODYLESS typedef sitting apart from its body -- `struct cte { cap_t
    // cap; };` on one line and `typedef struct cte cte_t;` four lines later.
    // `struct_field_types` files the fields under the TAG, so a variable
    // declared `cte_t *` resolves to a struct name nothing in that map holds
    // and the field type comes back unresolved. Without this hop the guard
    // never fires on the very findings it exists for.
    struct_typedef_aliases: &'a HashMap<String, String>,
    // Every function name the prescan saw DECLARED or DEFINED anywhere in the
    // project (`ProjectContext::known_functions`). The field guard fires only
    // when the callee is absent from this set -- see
    // `track_allocation_guarded`.
    known_functions: &'a HashSet<String>,
    // Every function-like macro the prescan collected project-wide
    // (`ProjectContext::function_macros`). Needed only to resolve a field
    // access whose base is a cast macro rather than a variable -- see
    // `macro_cast_pointer_type`.
    function_macros: &'a HashMap<String, FunctionMacro>,
    // Names of functions that never return to their caller, from the prescan
    // (headers included) unioned with this file's own declarations. A call to
    // one ends a branch the way `return` does (task 1076).
    noreturn_names: &'a HashSet<String>,
}

#[derive(Debug, Clone)]
struct AllocInfo {
    line: usize,
    column: usize,
    alloc_type: String,
}

/// The subset of `MemoryLeakAnalyzer`'s fields that are forked/reset/merged
/// across `if`/`switch` branches.
#[derive(Clone)]
struct LeakBranchState {
    freed_memory: HashMap<String, (usize, usize)>,
    null_variables: HashSet<String>,
}

impl LeakBranchState {
    fn fork(analyzer: &MemoryLeakAnalyzer) -> Self {
        Self {
            freed_memory: analyzer.freed_memory.clone(),
            null_variables: analyzer.null_variables.clone(),
        }
    }

    fn restore(&self, analyzer: &mut MemoryLeakAnalyzer) {
        analyzer.freed_memory = self.freed_memory.clone();
        analyzer.null_variables = self.null_variables.clone();
    }
}

// (alloc_info, free_info, loop_condition), as returned by
// `MemoryLeakAnalyzer::find_loop_array_pattern` plus the loop's own
// condition text.
type LoopArrayPattern = (
    Option<(String, bool)>,
    Option<(String, bool)>,
    Option<String>,
);

/// Explicit continuation-stack frames driving `MemoryLeakAnalyzer::
/// analyze_node` (task 295) — see that method's doc comment for why.
enum Frame<'a> {
    Visit(Node<'a>),
    /// Resume an `if`'s else-branch handling once the then-branch's own
    /// subtree (pushed on top of this frame) has fully drained.
    AfterTrueBranch {
        if_node: Node<'a>,
        saved_state: LeakBranchState,
        saved_allocated: HashMap<String, AllocInfo>,
        true_has_return: bool,
        else_has_return: bool,
        else_clause: Option<Node<'a>>,
        truthiness_var: Option<String>,
        non_null_check_var: Option<String>,
    },
    /// Merge then/else results once the else-branch's own subtree has fully
    /// drained.
    AfterElseBranch {
        if_node: Node<'a>,
        saved_state: LeakBranchState,
        saved_allocated: HashMap<String, AllocInfo>,
        true_has_return: bool,
        else_has_return: bool,
        true_state: LeakBranchState,
    },
    /// Reset to `pre_state` and walk the next `switch` case, once the
    /// previous case's own subtree has fully drained.
    SwitchNextCase {
        remaining_reversed: Vec<Node<'a>>,
        pre_state: LeakBranchState,
    },
    /// Decrement loop-nesting bookkeeping (and, for `for`, record the array
    /// alloc/free loop-condition pattern) once the loop body's own subtree
    /// has fully drained.
    ExitLoop {
        array_pattern: Option<LoopArrayPattern>,
    },
}

fn push_children<'a>(stack: &mut Vec<Frame<'a>>, node: &Node<'a>) {
    let count = node.child_count();
    for i in (0..count).rev() {
        if let Some(child) = node.child(i) {
            stack.push(Frame::Visit(child));
        }
    }
}

impl<'a> MemoryLeakAnalyzer<'a> {
    fn new(
        function_summaries: &'a HashMap<String, FunctionSummary>,
        value_only_globals: &'a HashSet<String>,
        struct_field_types: &'a HashMap<String, HashMap<String, String>>,
        struct_typedef_aliases: &'a HashMap<String, String>,
        known_functions: &'a HashSet<String>,
        function_macros: &'a HashMap<String, FunctionMacro>,
        noreturn_names: &'a HashSet<String>,
    ) -> Self {
        Self {
            allocated_memory: HashMap::new(),
            freed_memory: HashMap::new(),
            escaped_memory: HashSet::new(),
            null_variables: HashSet::new(),
            double_free_violations: Vec::new(),
            leak_violations: Vec::new(),
            in_loop: false,
            loop_depth: 0,
            label_frees: HashMap::new(),
            goto_freed_states: HashMap::new(),
            discarded_label_frees: HashMap::new(),
            realloc_relations: HashMap::new(),
            signal_registered: false,
            loop_array_patterns: HashMap::new(),
            function_summaries,
            function_params: HashSet::new(),
            deref_allocated_params: HashSet::new(),
            static_variables: HashSet::new(),
            value_only_locals: HashSet::new(),
            value_only_globals,
            value_only_fields: HashSet::new(),
            struct_field_types,
            struct_typedef_aliases,
            known_functions,
            function_macros,
            noreturn_names,
        }
    }

    fn analyze_function(
        &mut self,
        func_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(body) = func_node.child_by_field_name("body") {
            self.function_params = function_summary::collect_param_names(func_node, source)
                .into_iter()
                .filter(|n| !n.is_empty())
                .collect();
            self.static_variables = Self::collect_static_variable_names(&body, source);
            self.value_only_locals = Self::collect_value_only_locals(&body, source);
            self.value_only_fields = Self::collect_value_only_fields(
                func_node,
                &body,
                source,
                self.struct_field_types,
                self.struct_typedef_aliases,
                self.function_macros,
            );

            // Pre-analysis: collect what variables are freed at each label
            self.goto_freed_states.clear();
            self.discarded_label_frees.clear();
            self.collect_label_frees(&body, source);

            // Main pass: collect all memory operations and detect double-frees
            self.analyze_node(&body, source);

            // Add double-free violations found during analysis
            violations.append(&mut self.double_free_violations);

            // Add leak violations found at early returns
            violations.append(&mut self.leak_violations);

            // Final pass: check for leaks at end of function. The state the
            // walk ends on is whatever the last statement left, which after a
            // goto-only label is that label's entry state -- so re-credit the
            // frees dropped there. They happened on a real path (the one that
            // returns before the label); dropping them is right for judging a
            // double free inside the label block and wrong for judging a leak
            // at the end of the function.
            let discarded = std::mem::take(&mut self.discarded_label_frees);
            for (var, pos) in discarded {
                self.freed_memory.entry(var).or_insert(pos);
            }
            self.detect_leaks(violations);
        }
    }

    /// Find array allocation or free pattern in a for loop
    /// Returns (array_base, is_subscript) if found
    fn find_loop_array_pattern(
        &self,
        node: &Node,
        source: &str,
        is_alloc: bool,
    ) -> Option<(String, bool)> {
        if is_alloc {
            // Looking for array[i] = malloc() pattern
            let assign = query::find_first_descendant(*node, |n| {
                n.kind() == "assignment_expression"
                    && n.child_by_field_name("left")
                        .is_some_and(|left| left.kind() == "subscript_expression")
                    && n.child_by_field_name("right")
                        .is_some_and(|right| self.is_allocation_call(&right, source))
            })?;
            let left = assign.child_by_field_name("left")?;
            // Extract array base (e.g., "array" from "array[i]")
            let base = left.child_by_field_name("argument")?;
            Some((ast_utils::get_node_text_owned(&base, source), true))
        } else {
            // Looking for free(array[i]) pattern
            let call = query::find_first_descendant(*node, |n| {
                if n.kind() != "call_expression" {
                    return false;
                }
                let Some(function) = n.child_by_field_name("function") else {
                    return false;
                };
                if ast_utils::get_node_text_owned(&function, source) != "free" {
                    return false;
                }
                let Some(arguments) = n.child_by_field_name("arguments") else {
                    return false;
                };
                (0..arguments.child_count())
                    .filter_map(|i| arguments.child(i))
                    .any(|arg| arg.kind() == "subscript_expression")
            })?;
            let arguments = call.child_by_field_name("arguments")?;
            let arg = (0..arguments.child_count())
                .filter_map(|i| arguments.child(i))
                .find(|arg| arg.kind() == "subscript_expression")?;
            let base = arg.child_by_field_name("argument")?;
            Some((ast_utils::get_node_text_owned(&base, source), true))
        }
    }

    /// Check for macro calls that might hide early returns (e.g., CHECK_AND_RETURN, ASSERT_RETURN)
    fn check_for_return_macro(&mut self, node: &Node, source: &str) {
        // Find call_expression children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "call_expression" {
                    if let Some(function) = child.child_by_field_name("function") {
                        let func_name = ast_utils::get_node_text_owned(&function, source);
                        let upper_name = func_name.to_uppercase();

                        // Heuristic: macro names containing RETURN, EXIT, or similar might hide early returns
                        if upper_name.contains("RETURN")
                            || upper_name.contains("EXIT")
                            || upper_name.contains("ABORT")
                        {
                            // Check if there's allocated memory that would be leaked
                            let call_pos = child.start_position();
                            for (var_name, alloc_info) in &self.allocated_memory {
                                if self.escaped_memory.contains(var_name)
                                    || self.freed_memory.contains_key(var_name)
                                    || self.null_variables.contains(var_name)
                                    || self.static_variables.contains(var_name)
                                    || var_name.contains('@')
                                {
                                    continue;
                                }

                                self.leak_violations.push(RuleViolation {
                                    rule_id: "MEM31-C".to_string(),
                                    severity: Severity::High,
                                    message: format!(
                                        "Potential memory leak: '{}' allocated with '{}' may not be freed if {} causes early return",
                                        var_name, alloc_info.alloc_type, func_name
                                    ),
                                    file_path: String::new(),
                                    line: call_pos.row + 1,
                                    column: call_pos.column + 1,
                                    suggestion: Some(format!(
                                        "Free '{}' before {} or restructure to avoid potential leak",
                                        var_name, func_name
                                    )),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    /// Collect the names of local variables declared `static` within this
    /// function body -- their storage persists for the program's lifetime,
    /// so not freeing them before the function returns isn't a leak
    /// (MEM31-C-EX2).
    fn collect_static_variable_names(body: &Node, source: &str) -> HashSet<String> {
        let mut names = HashSet::new();
        for decl in query::find_descendants_of_kind(*body, "declaration") {
            let mut cursor = decl.walk();
            let is_static = decl.children(&mut cursor).any(|c| {
                c.kind() == "storage_class_specifier"
                    && ast_utils::get_node_text(&c, source) == "static"
            });
            if !is_static {
                continue;
            }
            let mut cursor = decl.walk();
            for child in decl.children(&mut cursor) {
                let declarator = match child.kind() {
                    "init_declarator" => child.child_by_field_name("declarator"),
                    "pointer_declarator" | "identifier" | "array_declarator" => Some(child),
                    _ => None,
                };
                if let Some(mut d) = declarator {
                    // Unwrap pointer_declarator layers to reach the identifier.
                    while d.kind() == "pointer_declarator" {
                        match d.child_by_field_name("declarator") {
                            Some(inner) => d = inner,
                            None => break,
                        }
                    }
                    if d.kind() == "identifier" {
                        names.insert(ast_utils::get_node_text(&d, source).to_string());
                    }
                }
            }
        }
        names
    }

    /// Collect the locals that provably cannot hold heap memory: declared
    /// with a plain (non-pointer, non-array) declarator *and* never used
    /// through any pointer-shaped operation in the whole body.
    ///
    /// This exists to corroborate `is_allocation_call`'s name-shape
    /// heuristic (`*_new`, `create_*`, `*_alloc`, `*_dup`, ...), which is a
    /// guess about an unseen callee, not evidence. seL4 builds its
    /// capability/page-table types with a code generator whose value
    /// constructors are named exactly like that (`pte_new`,
    /// `cap_frame_cap_new`, `seL4_Fault_VMFault_new`) but return a small
    /// struct *by value* — `pte_t pte = pte_new(...)` is a register/stack
    /// value, so "not freed" is never a leak (task 580).
    ///
    /// A pointer typedef (`typedef struct foo *foo_t;`) declared without a
    /// `*` is the case this deliberately does not exclude on the declarator
    /// alone: any such variable that really holds heap memory gets
    /// dereferenced, indexed, or NULL-checked somewhere, and each of those
    /// uses takes it back out of this set.
    fn collect_value_only_locals(body: &Node, source: &str) -> HashSet<String> {
        let mut candidates = HashSet::new();
        for decl in query::find_descendants_of_kind(*body, "declaration") {
            let mut cursor = decl.walk();
            for child in decl.children(&mut cursor) {
                let declarator = match child.kind() {
                    "init_declarator" => child.child_by_field_name("declarator"),
                    "pointer_declarator" | "identifier" | "array_declarator" => Some(child),
                    _ => None,
                };
                let Some(d) = declarator else { continue };
                if declarator_utils::is_pointer_declarator(&d)
                    || declarator_utils::is_array_declarator(&d)
                    || declarator_utils::is_function_declarator(&d)
                {
                    continue;
                }
                let name = ast_utils::get_identifier_from_declarator(&d, source);
                if !name.is_empty() {
                    candidates.insert(name);
                }
            }
        }

        if candidates.is_empty() {
            return candidates;
        }

        for node in query::find_descendants(*body, |n| {
            matches!(
                n.kind(),
                "field_expression"
                    | "pointer_expression"
                    | "subscript_expression"
                    | "binary_expression"
            )
        }) {
            for used in pointer_shaped_operand_names(&node, source) {
                candidates.remove(&used);
            }
        }

        candidates
    }

    /// Collect the struct-field assignment targets that provably cannot hold
    /// heap memory: the field's DECLARED TYPE is positively a non-pointer,
    /// and the field is never used through a pointer-shaped operation
    /// anywhere in the body.
    ///
    /// The field-target counterpart of [`collect_value_only_locals`], and it
    /// exists because the guard those sets apply is keyed on the ROOT
    /// variable's declared shape. For `callerSlot->cap = cap_null_cap_new()`
    /// the root is a genuine `cte_t *`, so `value_only_locals` and
    /// `value_only_globals` both correctly decline to match and the
    /// `*_new` name-shape guess about an unseen callee stands unchallenged.
    /// The evidence that settles it is one level in: `struct cte` declares
    /// `cap_t cap;`, a struct held BY VALUE, so the call's result is a
    /// register/stack value and "not freed" is not a leak.
    ///
    /// Keying on the field type rather than on the callee's return type is
    /// deliberate. The callee's return type is the more direct evidence and
    /// is simply not available here: seL4's bitfield value constructors
    /// (`cap_null_cap_new`, `seL4_Fault_NullFault_new`, `call_stack_new`) are
    /// declared only in `<object/structures_gen.h>`, emitted at build time by
    /// `tools/bitfield_gen.py` and never on disk -- the case
    /// `ProjectContext::unresolved_project_headers` already records. No
    /// declaration means no return type to read, whereas the struct that
    /// receives the value is ordinary source we do parse.
    ///
    /// A pointer TYPEDEF spelled without a `*` (`typedef struct foo *foo_t;`)
    /// is why the type test alone is not the whole predicate: the field type
    /// resolves to a bare name that looks like a value. The body scan is what
    /// covers it -- a field that really holds heap memory gets dereferenced,
    /// indexed, or NULL-checked somewhere, and any one of those uses takes it
    /// back out of this set. Same one-directional bargain the locals version
    /// makes: positive evidence of non-pointer-ness suppresses, absence of
    /// evidence never does.
    fn collect_value_only_fields(
        func_node: &Node,
        body: &Node,
        source: &str,
        struct_field_types: &HashMap<String, HashMap<String, String>>,
        struct_typedef_aliases: &HashMap<String, String>,
        function_macros: &HashMap<String, FunctionMacro>,
    ) -> HashSet<String> {
        if struct_field_types.is_empty() {
            return HashSet::new();
        }
        let mut type_map = overflow_helpers::collect_variable_types(func_node, source);
        // A macro-wrapped base carries its own type in the cast, so the
        // macro path stays available in a function that declares nothing.
        if type_map.is_empty() && function_macros.is_empty() {
            return HashSet::new();
        }
        // Rewrite each declared type's struct name to the TAG its fields are
        // actually filed under, so `cte_t *` looks up as `cte *`. Done here
        // rather than by merging the alias into `struct_field_types` because
        // that map is shared with four other rules, and filing aliases in it
        // would move their finding sets as a side effect of this fix (see
        // `ProjectContext::struct_typedef_aliases`).
        if !struct_typedef_aliases.is_empty() {
            for declared in type_map.values_mut() {
                let Some(struct_name) = ast_utils::extract_struct_name_from_type(declared) else {
                    continue;
                };
                if let Some(tag) = struct_typedef_aliases.get(struct_name) {
                    *declared = declared.replacen(struct_name, tag, 1);
                }
            }
        }

        let mut candidates = HashSet::new();
        for assign in query::find_descendants_of_kind(*body, "assignment_expression") {
            let Some(left) = assign.child_by_field_name("left") else {
                continue;
            };
            if left.kind() != "field_expression" {
                continue;
            }
            let resolved = ast_utils::resolve_field_expression_type(
                &left,
                source,
                &type_map,
                struct_field_types,
            )
            .or_else(|| {
                resolve_macro_based_field_type(
                    &left,
                    source,
                    struct_field_types,
                    struct_typedef_aliases,
                    function_macros,
                )
            });
            let Some(field_type) = resolved else {
                continue;
            };
            if ast_utils::is_pointer_type(&field_type)
                || ast_utils::is_array_parameter_type(&field_type)
            {
                continue;
            }
            candidates.insert(ast_utils::get_node_text_owned(&left, source));
        }

        if candidates.is_empty() {
            return candidates;
        }

        for node in query::find_descendants(*body, |n| {
            matches!(
                n.kind(),
                "field_expression"
                    | "pointer_expression"
                    | "subscript_expression"
                    | "binary_expression"
            )
        }) {
            for used in pointer_shaped_field_texts(&node, source) {
                candidates.remove(&used);
            }
        }

        candidates
    }

    /// True if `alloc_type` (the callee name recorded in `AllocInfo`) was
    /// recognized as an allocator *only* by `is_allocation_call`'s name-shape
    /// heuristic — neither a standard allocator nor a callee whose computed
    /// summary says it returns an allocation.
    fn is_name_heuristic_allocator(&self, alloc_type: &str) -> bool {
        !call_roles::is_allocator_call(alloc_type)
            && !self
                .function_summaries
                .get(alloc_type)
                .is_some_and(|summary| summary.returns_allocation)
    }

    /// Record `var_name` as holding allocated memory, unless the allocation
    /// was a bare name-shape guess about a variable that cannot be a pointer
    /// (see `collect_value_only_locals`).
    fn track_allocation(&mut self, var_name: String, info: AllocInfo) -> bool {
        let guard_name = var_name.clone();
        self.track_allocation_guarded(var_name, guard_name, info)
    }

    /// Like `track_allocation`, but checks `value_only_locals` (and its
    /// project-wide counterpart `value_only_globals`, task 652) against
    /// `guard_name` rather than the tracked `var_name` key itself. Needed
    /// for a struct-field/array-element target (`fc_ret.remainder = ...`),
    /// where the tracked key is the whole field expression's text but the
    /// pointer-evidence guard is about the *root* variable's declared shape
    /// (`fc_ret`) -- without this split, a field assignment on a plain
    /// value-type local never matches anything in `value_only_locals`
    /// (which only ever holds bare declared identifiers), so the guard
    /// silently never fires for the field-target path (task 651).
    fn track_allocation_guarded(
        &mut self,
        var_name: String,
        guard_name: String,
        info: AllocInfo,
    ) -> bool {
        // The field guard carries one extra condition the other two do not:
        // the callee must be absent from `known_functions`, i.e. the project
        // declares it nowhere at all.
        //
        // The name-shape heuristic is, in this rule's own words, "a guess
        // about an unseen callee". Where the callee IS seen, that guess is not
        // what is speaking -- the real inter-procedural analysis is -- and a
        // type guess about the DESTINATION must not overrule it. curl's
        // `addr_ctx->thread_hnd = Curl_thread_create(...)` is the case that
        // settles it: `curl_thread_t` is a POINTER typedef spelled without a
        // `*`, so the field looks like a value, and the body scan misses it
        // too because the null test is written against curl's own
        // `curl_thread_t_null` sentinel rather than `NULL`. Suppressing there
        // would discard a genuine allocation -- `Curl_thread_create` really
        // does `curlx_malloc(sizeof(pthread_t))`. Its prototype is right there
        // in `lib/curl_threads.h`, which is what this condition reads.
        //
        // seL4's value constructors are the opposite shape and the reason the
        // guard exists: `cap_null_cap_new` and friends are declared ONLY in
        // the build-time-generated `<object/structures_gen.h>`, so the project
        // knows the name from call sites alone. Nothing but the destination's
        // type is available to judge them by.
        let value_only_target = self.value_only_locals.contains(&guard_name)
            || self.value_only_globals.contains(&guard_name)
            || (self.value_only_fields.contains(&var_name)
                && !self.known_functions.contains(&info.alloc_type));
        if value_only_target && self.is_name_heuristic_allocator(&info.alloc_type) {
            return false;
        }
        self.allocated_memory.insert(var_name, info);
        true
    }

    /// Pre-analyze function to find what variables are freed at each labeled statement
    fn collect_label_frees(&mut self, node: &Node, source: &str) {
        for label in query::find_descendants_of_kind(*node, "labeled_statement") {
            // Get the label name
            if let Some(label_node) = label.child(0) {
                if label_node.kind() == "statement_identifier" {
                    let label_name = ast_utils::get_node_text_owned(&label_node, source);
                    // Collect all free() calls reachable from this label
                    let mut freed_vars = HashSet::new();
                    self.collect_frees_in_label(&label, source, &mut freed_vars);
                    self.label_frees.insert(label_name, freed_vars);
                }
            }
        }
    }

    /// Collect all free() calls reachable from a labeled statement. Calls
    /// nested inside a `return` statement's own expression are excluded (a
    /// `return_statement` node prunes further descent into its children in
    /// the original recursive walk) — replicated here by filtering out any
    /// `call_expression` with a `return_statement` ancestor. A label can
    /// never be lexically nested inside a `return` expression in valid C, so
    /// walking the full (unbounded) ancestor chain from each call cannot
    /// cross above `node` and pick up an unrelated `return_statement`.
    ///
    /// A custom deallocator counts here for the same reason it counts in the
    /// main walk (`process_custom_deallocator`): hostap's cleanup labels free
    /// through `EVP_PKEY_free`/`EC_POINT_new`-style wrappers, never through
    /// bare `free`, so a prescan that recognized only `free` claimed those
    /// labels cleaned up nothing and every `goto` into one looked like a
    /// leaked allocation. Reading the same predicate keeps the prescan and
    /// the walk from disagreeing about what a free is.
    fn collect_frees_in_label(&self, node: &Node, source: &str, freed_vars: &mut HashSet<String>) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if query::find_ancestor(call, |a| a.kind() == "return_statement").is_some() {
                continue;
            }
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = ast_utils::get_node_text_owned(&function, source);
                if func_name == "free" || self.is_deallocation_call(&func_name) {
                    if let Some(arguments) = call.child_by_field_name("arguments") {
                        for i in 0..arguments.child_count() {
                            if let Some(arg) = arguments.child(i) {
                                // `&var` reaches a deallocator that nulls its
                                // out-parameter -- same spelling the walk
                                // accepts.
                                let inner = if arg.kind() == "pointer_expression" {
                                    arg.child_by_field_name("argument")
                                } else {
                                    Some(arg)
                                };
                                let Some(inner) = inner else { continue };
                                if matches!(
                                    inner.kind(),
                                    "identifier" | "field_expression" | "subscript_expression"
                                ) {
                                    let var_name = ast_utils::get_node_text_owned(&inner, source);
                                    freed_vars.insert(var_name);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Entry point: analyze a function body (or any subtree) using an
    /// explicit heap-allocated frame stack instead of native recursion
    /// (task 295). `analyze_node`/`analyze_children`/`analyze_if`/
    /// `analyze_switch`/`analyze_for_loop`/`analyze_simple_loop`/
    /// `process_statement` previously formed a mutually-recursive walk whose
    /// depth tracked C statement nesting — deeply/adversarially nested
    /// input (Juliet-style generated code) could overflow the native call
    /// stack. This is a pure mechanical conversion: dispatch, traversal
    /// order (left-to-right, preorder), and branch-merge policy for `if`
    /// (freed_memory/null_variables) are unchanged, including the
    /// pre-existing quirk that `analyze_switch` never merges/restores state
    /// after its last case (state is left as whatever that case produced).
    /// Note `analyze_children`'s original recursion, unlike MEM30-C's,
    /// never filtered out `#if 0` subtrees — that omission is preserved
    /// here too, not fixed under cover of this refactor.
    fn analyze_node(&mut self, node: &Node, source: &str) {
        let mut stack: Vec<Frame> = vec![Frame::Visit(*node)];
        while let Some(frame) = stack.pop() {
            match frame {
                Frame::Visit(n) => self.visit(n, source, &mut stack),
                Frame::AfterTrueBranch {
                    if_node,
                    saved_state,
                    saved_allocated,
                    true_has_return,
                    else_has_return,
                    else_clause,
                    truthiness_var,
                    non_null_check_var,
                } => self.after_true_branch(
                    if_node,
                    saved_state,
                    saved_allocated,
                    true_has_return,
                    else_has_return,
                    else_clause,
                    truthiness_var,
                    non_null_check_var,
                    &mut stack,
                ),
                Frame::AfterElseBranch {
                    if_node,
                    saved_state,
                    saved_allocated,
                    true_has_return,
                    else_has_return,
                    true_state,
                } => {
                    let else_state = LeakBranchState::fork(self);
                    Self::finish_if(
                        self,
                        &if_node,
                        &saved_state,
                        &saved_allocated,
                        true_has_return,
                        else_has_return,
                        &true_state,
                        &else_state,
                        true,
                    );
                }
                Frame::SwitchNextCase {
                    remaining_reversed,
                    pre_state,
                } => self.switch_next_case(remaining_reversed, pre_state, &mut stack),
                Frame::ExitLoop { array_pattern } => self.exit_loop(array_pattern),
            }
        }
    }

    /// Dispatch for a single visited node: leaf statements are handled
    /// directly; statements that need to suspend across a nested subtree
    /// (`if`/`switch`/loops) push continuation frames instead of recursing.
    fn visit<'n>(&mut self, n: Node<'n>, source: &str, stack: &mut Vec<Frame<'n>>) {
        match n.kind() {
            "declaration" | "expression_statement" => {
                self.visit_declaration_or_expr(n, source, stack)
            }
            "assignment_expression" => self.process_assignment(&n, source),
            "call_expression" => self.process_call(&n, source),
            "return_statement" => self.process_return(&n, source),
            "goto_statement" => self.analyze_goto(&n, source),
            "labeled_statement" => self.visit_labeled_statement(n, source, stack),
            "for_statement" => self.visit_for_statement(n, source, stack),
            "while_statement" | "do_statement" => self.visit_while_do_statement(stack, n),
            "if_statement" => self.visit_if_statement(n, source, stack),
            "switch_statement" => self.visit_switch_statement(n, stack),
            _ => push_children(stack, &n),
        }
    }

    /// `declaration`/`expression_statement`: `init_declarator` children are
    /// handled inline (no further traversal, matching the original); any
    /// other child is deferred onto the stack instead of a recursive
    /// `analyze_node` call, preserving left-to-right order.
    fn visit_declaration_or_expr<'n>(
        &mut self,
        n: Node<'n>,
        source: &str,
        stack: &mut Vec<Frame<'n>>,
    ) {
        // Check for macro calls that might hide early returns
        self.check_for_return_macro(&n, source);
        let mut pending: Vec<Node> = Vec::new();
        for i in 0..n.child_count() {
            if let Some(child) = n.child(i) {
                if child.kind() == "init_declarator" {
                    self.process_init_declarator_child(&child, source);
                } else {
                    pending.push(child);
                }
            }
        }
        for child in pending.into_iter().rev() {
            stack.push(Frame::Visit(child));
        }
    }

    /// A label reached only by `goto` is not entered with the state of the
    /// code textually above it, so the linear walk must not carry that state
    /// in.
    ///
    /// pure-ftpd's `pure-pw.c` writes the ordinary cleanup-label shape:
    /// `free(file2); return PW_ERROR_UNEXPECTED_ERROR;` and then a `bye:`
    /// label whose own block frees `file2` again. Walking straight through
    /// left `file2` in `freed_memory` across the label, so the label's free
    /// read as a double free -- of a pointer that, on every path that can
    /// actually reach the label, had never been freed at all. The `return`
    /// ends that path first (task 1088).
    ///
    /// The entry state is recovered from the gotos themselves rather than
    /// discarded: `record_goto_entry_state` intersects `freed_memory` across
    /// every `goto` to this label, so a pointer counts as freed here only if
    /// every incoming jump had freed it. Intersecting rather than clearing
    /// matters for leaks -- a pointer freed before *all* of the gotos is
    /// still freed at the label and must not resurface as a leak at its
    /// return.
    ///
    /// Deliberately narrow: the state is left exactly as it is whenever the
    /// fall-through can reach the label, and whenever no `goto` to it has
    /// been visited yet (a forward jump, whose state this linear walk has
    /// not seen). Both keep today's behaviour instead of guessing.
    ///
    /// What is dropped here is kept in `discarded_label_frees` and given
    /// back to the end-of-function leak sweep. hostap's OpenSSL wrappers
    /// write the cleanup label *before* the error label -- `done:` frees
    /// everything and returns, then `fail:` nulls the result and jumps back
    /// to `done:` -- so the linear walk ends the function on `fail:`'s entry
    /// state. Without re-crediting, every pointer `done:` had freed read as
    /// a leak (22 of them across hostap alone).
    fn visit_labeled_statement<'n>(
        &mut self,
        n: Node<'n>,
        source: &str,
        stack: &mut Vec<Frame<'n>>,
    ) {
        if let Some(label) = n.child(0).filter(|c| c.kind() == "statement_identifier") {
            let name = ast_utils::get_node_text_owned(&label, source);
            if !self.fall_through_reaches(&n, source) {
                if let Some(entry_state) = self.goto_freed_states.get(&name).cloned() {
                    for (var, pos) in std::mem::replace(&mut self.freed_memory, entry_state) {
                        self.discarded_label_frees.entry(var).or_insert(pos);
                    }
                }
            }
        }
        push_children(stack, &n);
    }

    /// Fold the current `freed_memory` into the recorded entry state for
    /// `target_label`, keeping only what every `goto` to it agrees is freed.
    fn record_goto_entry_state(&mut self, target_label: &str) {
        match self.goto_freed_states.get_mut(target_label) {
            Some(state) => state.retain(|var, _| self.freed_memory.contains_key(var)),
            None => {
                self.goto_freed_states
                    .insert(target_label.to_string(), self.freed_memory.clone());
            }
        }
    }

    /// True if control can fall out of the statement textually preceding
    /// `label` into it. A `return`, `goto`, `break`, `continue` or a call to
    /// a function that never returns ends that path; anything else --
    /// including no preceding statement at all -- is treated as reaching,
    /// which is the conservative answer here.
    fn fall_through_reaches(&self, label: &Node, source: &str) -> bool {
        let mut prev = label.prev_named_sibling();
        while let Some(n) = prev {
            if n.kind() != "comment" {
                return self.statement_falls_through(&n, source);
            }
            prev = n.prev_named_sibling();
        }
        true
    }

    /// True if control can continue past `stmt` to the next statement in its
    /// block -- false for `return`/`goto`/`break`/`continue` and for a call
    /// to a function that never returns.
    fn statement_falls_through(&self, stmt: &Node, source: &str) -> bool {
        !matches!(
            stmt.kind(),
            "return_statement" | "goto_statement" | "break_statement" | "continue_statement"
        ) && !crate::analyze::noreturn::is_noreturn_call_statement(
            stmt,
            source,
            self.noreturn_names,
        )
    }

    fn visit_for_statement<'n>(&mut self, n: Node<'n>, source: &str, stack: &mut Vec<Frame<'n>>) {
        let loop_condition = n
            .child_by_field_name("condition")
            .map(|c| ast_utils::get_node_text_owned(&c, source));
        self.in_loop = true;
        self.loop_depth += 1;
        let alloc_info = self.find_loop_array_pattern(&n, source, true);
        let free_info = self.find_loop_array_pattern(&n, source, false);
        stack.push(Frame::ExitLoop {
            array_pattern: Some((alloc_info, free_info, loop_condition)),
        });
        push_children(stack, &n);
    }

    fn visit_while_do_statement<'n>(&mut self, stack: &mut Vec<Frame<'n>>, n: Node<'n>) {
        self.in_loop = true;
        self.loop_depth += 1;
        stack.push(Frame::ExitLoop {
            array_pattern: None,
        });
        push_children(stack, &n);
    }

    fn visit_if_statement<'n>(&mut self, n: Node<'n>, source: &str, stack: &mut Vec<Frame<'n>>) {
        let saved_state = LeakBranchState::fork(self);
        let saved_allocated = self.allocated_memory.clone();

        let null_check_var = self.get_null_check_variable(&n, source);
        let non_null_check_var = self.get_non_null_check_variable(&n, source);
        let truthiness_var = self.get_truthiness_check_variable(&n, source);

        let mut true_branch: Option<Node> = None;
        let mut else_clause: Option<Node> = None;
        for i in 0..n.child_count() {
            if let Some(child) = n.child(i) {
                if child.kind() == "compound_statement" && true_branch.is_none() {
                    true_branch = Some(child);
                } else if child.kind() == "else_clause" {
                    else_clause = Some(child);
                }
            }
        }

        let true_has_return = true_branch
            .as_ref()
            .map(|b| self.block_has_return(b, source))
            .unwrap_or(false);
        let else_has_return = else_clause
            .as_ref()
            .map(|e| self.block_has_return(e, source))
            .unwrap_or(false);

        if let Some(ref var_name) = null_check_var {
            self.null_variables.insert(var_name.clone());
        }
        self.clear_realloc_invalidation_if_related(&truthiness_var, n);
        self.clear_realloc_invalidation_if_related(&non_null_check_var, n);

        stack.push(Frame::AfterTrueBranch {
            if_node: n,
            saved_state,
            saved_allocated,
            true_has_return,
            else_has_return,
            else_clause,
            truthiness_var,
            non_null_check_var,
        });
        if let Some(branch) = true_branch {
            stack.push(Frame::Visit(branch));
        }
    }

    /// If `result_var` is a tracked realloc result, its old pointer's
    /// invalidation was already recorded when the realloc ran; a truthiness
    /// or non-NULL check on the result means the realloc succeeded, so the
    /// old pointer is (re-)treated as freed rather than dangling.
    fn clear_realloc_invalidation_if_related(
        &mut self,
        result_var: &Option<String>,
        if_node: Node,
    ) {
        let Some(result_var) = result_var else {
            return;
        };
        if let Some(old_ptr) = self.realloc_relations.get(result_var).cloned() {
            let pos = if_node.start_position();
            self.freed_memory
                .insert(old_ptr, (pos.row + 1, pos.column + 1));
        }
    }

    fn visit_switch_statement<'n>(&mut self, n: Node<'n>, stack: &mut Vec<Frame<'n>>) {
        let mut cases: Vec<Node> = Vec::new();
        if let Some(body) = n.child_by_field_name("body") {
            for i in 0..body.child_count() {
                if let Some(child) = body.child(i) {
                    if child.kind() == "case_statement" {
                        cases.push(child);
                    }
                }
            }
        }
        cases.reverse();
        stack.push(Frame::SwitchNextCase {
            remaining_reversed: cases,
            pre_state: LeakBranchState::fork(self),
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn after_true_branch<'n>(
        &mut self,
        if_node: Node<'n>,
        saved_state: LeakBranchState,
        saved_allocated: HashMap<String, AllocInfo>,
        true_has_return: bool,
        else_has_return: bool,
        else_clause: Option<Node<'n>>,
        truthiness_var: Option<String>,
        non_null_check_var: Option<String>,
        stack: &mut Vec<Frame<'n>>,
    ) {
        let true_state = LeakBranchState::fork(self);

        if let Some(else_node) = else_clause {
            saved_state.restore(self);
            if let Some(ref var_name) = truthiness_var {
                self.null_variables.insert(var_name.clone());
            }
            if let Some(ref var_name) = non_null_check_var {
                self.null_variables.insert(var_name.clone());
            }
            stack.push(Frame::AfterElseBranch {
                if_node,
                saved_state,
                saved_allocated,
                true_has_return,
                else_has_return,
                true_state,
            });
            stack.push(Frame::Visit(else_node));
        } else {
            // No else clause - the "else path" is just the saved state
            Self::finish_if(
                self,
                &if_node,
                &saved_state,
                &saved_allocated,
                true_has_return,
                else_has_return,
                &true_state,
                &saved_state,
                false,
            );
        }
    }

    fn switch_next_case<'n>(
        &mut self,
        mut remaining_reversed: Vec<Node<'n>>,
        pre_state: LeakBranchState,
        stack: &mut Vec<Frame<'n>>,
    ) {
        if let Some(case) = remaining_reversed.pop() {
            pre_state.restore(self);
            stack.push(Frame::SwitchNextCase {
                remaining_reversed,
                pre_state: pre_state.clone(),
            });
            stack.push(Frame::Visit(case));
        }
        // else: no more cases - chain ends, self stays as whatever the last
        // case left it (pre-existing quirk, preserved: no merge/restore
        // after the loop).
    }

    fn exit_loop(&mut self, array_pattern: Option<LoopArrayPattern>) {
        if let Some((alloc_info, free_info, loop_condition)) = array_pattern {
            if let Some((array_base, _)) = alloc_info {
                if let Some(cond) = &loop_condition {
                    let entry = self
                        .loop_array_patterns
                        .entry(array_base)
                        .or_insert((None, None));
                    entry.0 = Some(cond.clone());
                }
            }
            if let Some((array_base, _)) = free_info {
                if let Some(cond) = &loop_condition {
                    let entry = self
                        .loop_array_patterns
                        .entry(array_base)
                        .or_insert((None, None));
                    entry.1 = Some(cond.clone());
                }
            }
        }
        self.loop_depth -= 1;
        if self.loop_depth == 0 {
            self.in_loop = false;
        }
    }

    /// Merge post-then/post-else state back onto `analyzer` after an `if`,
    /// per which branch(es) unconditionally return, and report conditional
    /// leaks when neither returns and both branches exist. Direct
    /// transcription of the original `analyze_if`'s final merge block.
    #[allow(clippy::too_many_arguments)]
    fn finish_if(
        analyzer: &mut Self,
        if_node: &Node,
        saved_state: &LeakBranchState,
        saved_allocated: &HashMap<String, AllocInfo>,
        true_has_return: bool,
        else_has_return: bool,
        true_state: &LeakBranchState,
        else_state: &LeakBranchState,
        else_clause_present: bool,
    ) {
        if true_has_return && else_has_return {
            saved_state.restore(analyzer);
        } else if true_has_return {
            else_state.restore(analyzer);
        } else if else_has_return {
            true_state.restore(analyzer);
        } else if else_clause_present {
            analyzer.report_conditional_leaks(
                if_node,
                saved_allocated,
                &saved_state.null_variables,
                &true_state.freed_memory,
                &else_state.freed_memory,
                &else_state.null_variables,
            );
            let mut merged = true_state.freed_memory.clone();
            for (k, v) in else_state.freed_memory.clone() {
                merged.entry(k).or_insert(v);
            }
            analyzer.freed_memory = merged;
        }
        // else: no else clause - just keep current (true-branch) state
    }

    /// Inline body of the original `process_statement`'s `init_declarator`
    /// branch — allocation bookkeeping only, never recurses.
    fn process_init_declarator_child(&mut self, child: &Node, source: &str) {
        if let Some(declarator) = child.child_by_field_name("declarator") {
            let var_name = self.get_variable_name(&declarator, source);

            if let Some(value) = child.child_by_field_name("value") {
                if self.is_allocation_call(&value, source) {
                    let pos = value.start_position();
                    let alloc_type = self.get_allocation_type(&value, source);

                    // Special handling for realloc: track relationship for later
                    if alloc_type == "realloc" {
                        self.handle_realloc_in_decl(&var_name, &value, source);
                    }

                    let tracked = self.track_allocation(
                        var_name.clone(),
                        AllocInfo {
                            line: pos.row + 1,
                            column: pos.column + 1,
                            alloc_type: alloc_type.clone(),
                        },
                    );
                    // If signal handler has been registered, warn about potential leak
                    if tracked && self.signal_registered {
                        self.leak_violations.push(RuleViolation {
                            rule_id: "MEM31-C".to_string(),
                            severity: Severity::High,
                            message: format!(
                                "Potential memory leak: '{}' allocated with '{}' may not be freed if signal handler terminates the program",
                                var_name, alloc_type
                            ),
                            file_path: String::new(),
                            line: pos.row + 1,
                            column: pos.column + 1,
                            suggestion: Some(format!(
                                "Allocate '{}' before registering signal handlers, or ensure cleanup in signal handler",
                                var_name
                            )),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    /// A goto can bypass cleanup code; report leaks for allocations that aren't
    /// freed at the target label.
    fn analyze_goto(&mut self, node: &Node, source: &str) {
        // First, find the target label
        let mut target_label = String::new();
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "statement_identifier" {
                    target_label = ast_utils::get_node_text_owned(&child, source);
                    break;
                }
            }
        }

        self.record_goto_entry_state(&target_label);

        // Get what variables are freed at the target label
        let label_freed_vars = self.label_frees.get(&target_label).cloned();

        let goto_pos = node.start_position();
        for (var_name, alloc_info) in &self.allocated_memory {
            if self.escaped_memory.contains(var_name)
                || self.freed_memory.contains_key(var_name)
                || self.null_variables.contains(var_name)
                || self.static_variables.contains(var_name)
                || var_name.contains('@')
            {
                continue;
            }

            // Check if this variable is freed at the target label
            // Also check for field expression variants (e.g., bundle->data matches bundle)
            let is_freed_at_label = label_freed_vars.as_ref().is_some_and(|freed| {
                freed.contains(var_name)
                    || freed
                        .iter()
                        .any(|f| f.starts_with(&format!("{}->", var_name)))
                    || freed.iter().any(|f| {
                        // Check if var_name is a field and its container is freed
                        if let Some(base) = var_name.split("->").next() {
                            f == base
                        } else {
                            false
                        }
                    })
            });

            if is_freed_at_label {
                continue; // This variable is properly cleaned up at the label
            }

            self.leak_violations.push(RuleViolation {
                rule_id: "MEM31-C".to_string(),
                severity: Severity::High,
                message: format!(
                    "Potential memory leak: '{}' allocated with '{}' may not be freed due to goto",
                    var_name, alloc_info.alloc_type
                ),
                file_path: String::new(),
                line: goto_pos.row + 1,
                column: goto_pos.column + 1,
                suggestion: Some(format!(
                    "Ensure '{}' is freed before this goto or at the target label",
                    var_name
                )),
                ..Default::default()
            });
        }
    }

    /// When neither `if` branch returns, report allocations freed in the true branch
    /// but not the else branch (and not nulled there) as conditional leaks.
    #[allow(clippy::too_many_arguments)]
    fn report_conditional_leaks(
        &mut self,
        node: &Node,
        saved_allocated: &HashMap<String, AllocInfo>,
        saved_null: &HashSet<String>,
        true_freed: &HashMap<String, (usize, usize)>,
        else_freed: &HashMap<String, (usize, usize)>,
        else_null: &HashSet<String>,
    ) {
        let if_pos = node.start_position();
        for (var_name, alloc_info) in saved_allocated {
            // Skip variables that shouldn't be checked
            if self.escaped_memory.contains(var_name)
                || saved_null.contains(var_name)
                || self.static_variables.contains(var_name)
                || var_name.contains('@')
            {
                continue;
            }

            let freed_in_true = true_freed.contains_key(var_name);
            let freed_in_else = else_freed.contains_key(var_name);
            let null_in_else = else_null.contains(var_name);

            // Report leak only if freed in true but not else, and not null in else
            if freed_in_true && !freed_in_else && !null_in_else {
                self.leak_violations.push(RuleViolation {
                    rule_id: "MEM31-C".to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Conditional memory leak: '{}' allocated with '{}' is only freed in one branch",
                        var_name, alloc_info.alloc_type
                    ),
                    file_path: String::new(),
                    line: if_pos.row + 1,
                    column: if_pos.column + 1,
                    suggestion: Some(format!("Ensure '{}' is freed in both branches", var_name)),
                    ..Default::default()
                });
            }
        }
    }

    /// Handle realloc when used in a declaration - tracks the relationship for later analysis
    fn handle_realloc_in_decl(&mut self, result_var: &str, call_node: &Node, source: &str) {
        // Handle cast expressions
        let actual_call = if call_node.kind() == "cast_expression" {
            call_node.child_by_field_name("value")
        } else {
            Some(*call_node)
        };

        if let Some(call) = actual_call {
            if call.kind() == "call_expression" {
                if let Some(arguments) = call.child_by_field_name("arguments") {
                    for i in 0..arguments.child_count() {
                        if let Some(arg) = arguments.child(i) {
                            if arg.kind() != "," && arg.kind() != "(" && arg.kind() != ")" {
                                // First argument to realloc is the old pointer
                                if arg.kind() == "identifier" {
                                    let old_ptr = ast_utils::get_node_text_owned(&arg, source);
                                    // Track: result_var was assigned from realloc(old_ptr)
                                    self.realloc_relations
                                        .insert(result_var.to_string(), old_ptr);
                                }
                                break; // Only process first argument
                            }
                        }
                    }
                }
            }
        }
    }

    /// Walk down an lvalue expression (the target of a struct-field or
    /// array-element assignment) to find its root identifier, following
    /// `field_expression` -> `argument`, `subscript_expression` -> `argument`,
    /// `parenthesized_expression` unwrapping, and unary `*` dereference.
    /// Returns `(root_name, saw_deref)` where `saw_deref` is true if a `*`
    /// dereference or `[]` subscript was crossed en route to the root (task
    /// 306: distinguishes `cfg->field` — direct borrowed-struct-parameter
    /// access — from `(*out)->field` — an out-parameter pattern that may
    /// point at a struct this function itself just allocated).
    fn root_identifier_of_lvalue(&self, node: &Node, source: &str) -> Option<(String, bool)> {
        let mut current = *node;
        let mut saw_deref = false;
        loop {
            match current.kind() {
                "identifier" => {
                    return Some((ast_utils::get_node_text_owned(&current, source), saw_deref));
                }
                "field_expression" => {
                    current = current.child_by_field_name("argument")?;
                }
                "subscript_expression" => {
                    saw_deref = true;
                    current = current.child_by_field_name("argument")?;
                }
                "pointer_expression" => {
                    // `*p` and `&p` both parse as `pointer_expression` in
                    // this tree-sitter-c grammar (see points_to.rs), but
                    // `&p` can never appear as (part of) an lvalue chain --
                    // only `*p` can be assigned through -- so any
                    // pointer_expression reached while walking an
                    // assignment's LHS here is unambiguously a dereference.
                    saw_deref = true;
                    current = current.child_by_field_name("argument")?;
                }
                "parenthesized_expression" => {
                    current = current.named_child(0)?;
                }
                "unary_expression" => {
                    let op = current
                        .child_by_field_name("operator")
                        .map(|o| ast_utils::get_node_text_owned(&o, source))
                        .unwrap_or_default();
                    if op != "*" {
                        return None;
                    }
                    saw_deref = true;
                    current = current.child_by_field_name("argument")?;
                }
                _ => return None,
            }
        }
    }

    /// Is `left` (a struct-field/array-element lvalue) a leak candidate this
    /// function should be held responsible for, or does it reach into a
    /// caller-owned/borrowed struct via a bare function parameter (task
    /// 306)? A parameter's struct is only "owned" by this function if the
    /// parameter itself was used as an out-parameter that this function
    /// freshly allocated into (`*param = malloc(...)`); a plain
    /// `param->field = alloc()` is always borrowed.
    fn is_this_function_owned_field_target(&self, left: &Node, source: &str) -> bool {
        let Some((root, saw_deref)) = self.root_identifier_of_lvalue(left, source) else {
            // Couldn't determine a root identifier (unusual lvalue shape) -
            // preserve prior behavior and still track it.
            return true;
        };
        if !self.function_params.contains(&root) {
            return true;
        }
        saw_deref && self.deref_allocated_params.contains(&root)
    }

    /// Track `*param = malloc(...)`-shaped out-parameter allocations: this is
    /// the signal that a struct reached through `param` was freshly
    /// allocated by this function, not borrowed from the caller (task 306).
    fn record_deref_allocated_param(&mut self, left: &Node, right: &Node, source: &str) {
        let op = left
            .child_by_field_name("operator")
            .map(|o| ast_utils::get_node_text_owned(&o, source))
            .unwrap_or_default();
        if op != "*" || !self.is_allocation_call(right, source) {
            return;
        }
        let Some(arg) = left.child_by_field_name("argument") else {
            return;
        };
        if arg.kind() != "identifier" {
            return;
        }
        let name = ast_utils::get_node_text_owned(&arg, source);
        if self.function_params.contains(&name) {
            self.deref_allocated_params.insert(name);
        }
    }

    fn process_assignment(&mut self, node: &Node, source: &str) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            // `*out = malloc(...)` parses as "pointer_expression" in this
            // tree-sitter-c grammar, not "unary_expression" -- without this
            // arm, record_deref_allocated_param's out-parameter tracking
            // (task 306) never fired for the real dereference-assignment
            // pattern it exists to detect.
            if matches!(left.kind(), "unary_expression" | "pointer_expression") {
                self.record_deref_allocated_param(&left, &right, source);
                return;
            }

            // Handle field expressions on the left - track allocation if RHS is allocation
            // e.g., data->text = malloc(100) or array[i] = malloc(50)
            if left.kind() == "field_expression" || left.kind() == "subscript_expression" {
                // If right side is an allocation, track it with the full expression as key
                if self.is_allocation_call(&right, source) {
                    if !self.is_this_function_owned_field_target(&left, source) {
                        return;
                    }
                    let var_name = ast_utils::get_node_text_owned(&left, source);
                    let guard_name = self
                        .root_identifier_of_lvalue(&left, source)
                        .map(|(root, _)| root)
                        .unwrap_or_else(|| var_name.clone());
                    let pos = right.start_position();
                    let alloc_type = self.get_allocation_type(&right, source);
                    self.track_allocation_guarded(
                        var_name,
                        guard_name,
                        AllocInfo {
                            line: pos.row + 1,
                            column: pos.column + 1,
                            alloc_type,
                        },
                    );
                } else if right.kind() == "identifier" {
                    // If right side is an allocated variable, mark it as escaped
                    // e.g., list->head = new_node (new_node escapes)
                    let right_var = ast_utils::get_node_text_owned(&right, source);
                    if self.allocated_memory.contains_key(&right_var) {
                        self.escaped_memory.insert(right_var.clone());
                        // Also mark any field allocations belonging to this container as escaped
                        let field_prefix = format!("{}->", right_var);
                        let fields_to_escape: Vec<String> = self
                            .allocated_memory
                            .keys()
                            .filter(|k| k.starts_with(&field_prefix))
                            .cloned()
                            .collect();
                        for field in fields_to_escape {
                            self.escaped_memory.insert(field);
                        }
                    }
                }
                return;
            }

            // Handle identifiers for allocation tracking
            let var_name = if left.kind() == "identifier" {
                ast_utils::get_node_text_owned(&left, source)
            } else {
                return;
            };

            // Check if this variable was previously allocated
            let was_allocated = self.allocated_memory.contains_key(&var_name);

            // Check if assigning result of allocation
            if self.is_allocation_call(&right, source) {
                // If the variable was already allocated and not freed, it's a leak
                // -- unless the allocating call is the thing that released it.
                // `p = realloc(p, n)` and its wrappers consume the old block and
                // hand back a new one, so the old allocation never leaks.
                if was_allocated
                    && !self.freed_memory.contains_key(&var_name)
                    && !self.call_releases_var(&right, source, &var_name)
                {
                    // The old allocation is now leaked - we need to create a unique identifier for it
                    // Since we can't track the old allocation separately, we'll generate a violation now
                    if let Some(old_alloc) = self.allocated_memory.get(&var_name) {
                        // We'll mark this as leaked by creating a unique name for the old allocation
                        let leaked_name =
                            format!("{}@{}:{}", var_name, old_alloc.line, old_alloc.column);
                        self.allocated_memory.insert(leaked_name, old_alloc.clone());
                    }
                }

                // New allocation clears freed status (variable now points to valid memory)
                self.freed_memory.remove(&var_name);

                let pos = right.start_position();
                let alloc_type = self.get_allocation_type(&right, source);
                self.track_allocation(
                    var_name.clone(),
                    AllocInfo {
                        line: pos.row + 1,
                        column: pos.column + 1,
                        alloc_type,
                    },
                );
            } else if right.kind() == "identifier" {
                // Check if assigning allocated pointer to another variable
                let right_var = ast_utils::get_node_text_owned(&right, source);

                // Assignment of one pointer to another clears the freed status
                // (e.g., buffer = temp after realloc)
                self.freed_memory.remove(&var_name);

                if self.allocated_memory.contains_key(&right_var) {
                    // Transfer ownership
                    if let Some(alloc_info) = self.allocated_memory.get(&right_var).cloned() {
                        self.allocated_memory.insert(var_name, alloc_info);
                        // The original variable still holds the allocation until freed
                    }
                }
            } else if right.kind() == "null"
                || ast_utils::get_node_text_owned(&right, source) == "NULL"
            {
                // Setting to NULL doesn't free memory, potential leak if not freed before
                // If the variable was allocated and not freed, it's a leak
                if was_allocated && !self.freed_memory.contains_key(&var_name) {
                    if let Some(old_alloc) = self.allocated_memory.get(&var_name) {
                        let leaked_name =
                            format!("{}@{}:{}", var_name, old_alloc.line, old_alloc.column);
                        self.allocated_memory.insert(leaked_name, old_alloc.clone());
                    }
                }
            }
        }
    }

    fn process_call(&mut self, node: &Node, source: &str) {
        let Some(function) = node.child_by_field_name("function") else {
            return;
        };
        let func_name = ast_utils::get_node_text_owned(&function, source);

        // Check for signal() registration - may lead to async termination
        if func_name == "signal" {
            self.signal_registered = true;
        }

        // Check for termination calls that leak memory
        if matches!(
            func_name.as_str(),
            "abort" | "exit" | "_Exit" | "_exit" | "quick_exit" | "longjmp" | "siglongjmp"
        ) {
            self.report_termination_leaks(node, &func_name);
            return;
        }

        // Check for custom deallocation functions: destroy_*, free_*, delete_*, cleanup_*, release_*
        if self.is_deallocation_call(&func_name) {
            self.process_custom_deallocator(node, source, &func_name);
        }

        if func_name == "free" {
            self.process_free_call(node, source);
        } else if func_name == "realloc" {
            self.process_realloc_call(node, source);
        } else {
            self.process_freeing_callee(node, source, &func_name);
        }
    }

    /// Report leaks of still-live allocations at a termination call (abort/exit/longjmp).
    fn report_termination_leaks(&mut self, node: &Node, func_name: &str) {
        let call_pos = node.start_position();

        for (var_name, alloc_info) in &self.allocated_memory {
            if self.escaped_memory.contains(var_name)
                || self.freed_memory.contains_key(var_name)
                || self.null_variables.contains(var_name)
                || self.static_variables.contains(var_name)
                || var_name.contains('@')
            {
                continue;
            }

            self.leak_violations.push(RuleViolation {
                rule_id: "MEM31-C".to_string(),
                severity: Severity::High,
                message: format!(
                    "Memory leak: '{}' allocated with '{}' is not freed before {}()",
                    var_name, alloc_info.alloc_type, func_name
                ),
                file_path: String::new(),
                line: call_pos.row + 1,
                column: call_pos.column + 1,
                suggestion: Some(format!(
                    "Free '{}' before calling {}()",
                    var_name, func_name
                )),
                ..Default::default()
            });
        }
    }

    /// Handle a custom deallocator call (destroy_*, free_*, etc.): record double-frees
    /// for non-idempotent deallocators and mark the argument as freed.
    fn process_custom_deallocator(&mut self, node: &Node, source: &str, func_name: &str) {
        // Heuristic: functions with "safe" in the name or "destroy" prefix are typically
        // designed to be idempotent (set pointer to NULL after freeing)
        // Other custom deallocators like "cleanup_*" may not be safe to call twice
        let is_safe_deallocator = {
            let lower = func_name.to_lowercase();
            lower.contains("safe") || lower.starts_with("destroy_") || lower.ends_with("_destroy")
        };

        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut param_idx = 0usize;
        for i in 0..arguments.child_count() {
            let Some(arg) = arguments.child(i) else {
                continue;
            };
            if arg.kind() == "," || arg.kind() == "(" || arg.kind() == ")" {
                continue;
            }
            let this_param_idx = param_idx;
            param_idx += 1;
            let var_name = if arg.kind() == "pointer_expression" {
                // Handle &var pattern (address-of expression)
                arg.child_by_field_name("argument")
                    .filter(|op| op.kind() == "identifier")
                    .map(|op| ast_utils::get_node_text_owned(&op, source))
            } else if arg.kind() == "identifier" {
                Some(ast_utils::get_node_text_owned(&arg, source))
            } else {
                None
            };

            let Some(var_name) = var_name else {
                continue;
            };
            let free_pos = node.start_position();

            // Check for double-free only for non-safe deallocators
            if !is_safe_deallocator && self.freed_memory.contains_key(&var_name) {
                self.double_free_violations.push(RuleViolation {
                    rule_id: "MEM31-C".to_string(),
                    severity: Severity::High,
                    message: format!("Double free detected: '{}' was already freed", var_name),
                    file_path: String::new(),
                    line: free_pos.row + 1,
                    column: free_pos.column + 1,
                    suggestion: Some(format!(
                        "Remove this duplicate {}() call or set the pointer to NULL after first free",
                        func_name
                    )),
                    ..Default::default()
                });
            }

            // Mark as freed (for leak detection)
            self.freed_memory
                .insert(var_name.clone(), (free_pos.row + 1, free_pos.column + 1));

            // If the callee's summary shows it frees specific struct fields
            // off this parameter internally (e.g. `destroy_person(&p)` where
            // `destroy_person` does `free((*p)->name); free(*p);`), credit
            // those fields as freed here too — otherwise they read as leaks
            // even though ownership was transferred to the deallocator
            // (task 2: MEM31-C ownership model). `field` may itself be an
            // arrow-joined chain (e.g. "will->topic") for nested structs.
            if let Some(summary) = self.function_summaries.get(func_name) {
                if let Some(fields) = summary.frees_param_fields.get(&this_param_idx) {
                    for field in fields {
                        let field_key = format!("{}->{}", var_name, field);
                        self.freed_memory
                            .insert(field_key, (free_pos.row + 1, free_pos.column + 1));
                    }
                }
            }
        }
    }

    /// Handle a `free()` call: record double-frees and mark the argument plus any
    /// aliases (same allocation site) as freed.
    fn process_free_call(&mut self, node: &Node, source: &str) {
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        for i in 0..arguments.child_count() {
            let Some(arg) = arguments.child(i) else {
                continue;
            };
            // Handle identifiers, field expressions, and subscript expressions
            let var_name = match arg.kind() {
                "identifier" | "field_expression" | "subscript_expression" => {
                    // For field/subscript expressions like "container->data" or "arr[i]"
                    ast_utils::get_node_text_owned(&arg, source)
                }
                _ => continue,
            };

            if var_name.is_empty() {
                continue;
            }
            let free_pos = node.start_position();

            // Check for double-free: if already freed, report violation
            if self.freed_memory.contains_key(&var_name) {
                self.double_free_violations.push(RuleViolation {
                    rule_id: "MEM31-C".to_string(),
                    severity: Severity::High,
                    message: format!("Double free detected: '{}' was already freed", var_name),
                    file_path: String::new(),
                    line: free_pos.row + 1,
                    column: free_pos.column + 1,
                    suggestion: Some(format!(
                        "Remove this duplicate free() call or set '{}' = NULL after first free",
                        var_name
                    )),
                    ..Default::default()
                });
            }

            // Mark as freed
            self.freed_memory
                .insert(var_name.clone(), (free_pos.row + 1, free_pos.column + 1));

            // Also mark any aliases as freed
            let vars_to_free: Vec<String> = self
                .allocated_memory
                .iter()
                .filter_map(|(k, v)| {
                    if let Some(original) = self.allocated_memory.get(&var_name) {
                        if v.line == original.line && v.column == original.column {
                            Some(k.clone())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect();

            for v in vars_to_free {
                self.freed_memory
                    .insert(v, (free_pos.row + 1, free_pos.column + 1));
            }
        }
    }

    /// Handle a `realloc()` call: the first argument's old memory is freed.
    fn process_realloc_call(&mut self, node: &Node, source: &str) {
        // realloc can be used to free memory (when new size is 0) or reallocate
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut arg_count = 0;
        let mut first_arg = String::new();
        let free_pos = node.start_position();

        for i in 0..arguments.child_count() {
            if let Some(arg) = arguments.child(i) {
                if arg.kind() != "," && arg.kind() != "(" && arg.kind() != ")" {
                    if arg_count == 0 && arg.kind() == "identifier" {
                        first_arg = ast_utils::get_node_text_owned(&arg, source);
                    }
                    arg_count += 1;
                }
            }
        }

        if !first_arg.is_empty() {
            // realloc frees the old memory and allocates new
            self.freed_memory
                .insert(first_arg.clone(), (free_pos.row + 1, free_pos.column + 1));
        }
    }

    /// Handle a call to a user function whose prescan summary indicates it frees
    /// one of its parameters: mark the matching allocated argument as freed.
    ///
    /// Two argument shapes count. `release(p)` matches `frees_params` — the
    /// pointer value handed in is released. `safe_free(&p)` matches
    /// `frees_param_pointees` — the callee frees `*param`, so it is the
    /// caller's own variable that dies, and the argument names it by address.
    /// Casts and parentheses are transparent in both, which matters because
    /// the `void **` idiom is almost always written `safe_free((void **)&p)`.
    fn process_freeing_callee(&mut self, node: &Node, source: &str, func_name: &str) {
        // Check if passing allocated memory to a function that frees it.
        // Use prescan function summaries to determine if the callee frees
        // the parameter at the corresponding index.
        let Some(summary) = self.function_summaries.get(func_name) else {
            return;
        };
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut param_idx = 0usize;
        for i in 0..arguments.child_count() {
            if let Some(arg) = arguments.child(i) {
                if arg.kind() == "," || arg.kind() == "(" || arg.kind() == ")" {
                    continue;
                }
                if let Some((target, through_address_of)) = strip_call_argument(arg) {
                    let frees = if through_address_of {
                        summary.frees_param_pointees.contains(&param_idx)
                    } else {
                        summary.frees_params.contains(&param_idx)
                    };
                    let var_name = ast_utils::get_node_text_owned(&target, source);
                    if frees && self.allocated_memory.contains_key(&var_name) {
                        let free_pos = node.start_position();
                        self.freed_memory
                            .insert(var_name, (free_pos.row + 1, free_pos.column + 1));
                    }
                }
                param_idx += 1;
            }
        }
    }

    /// True when `expr` is a call that releases `var_name` as it runs: a
    /// project-local wrapper whose prescan summary frees the parameter `p` is
    /// passed to, either by value (`frees_params`, the safe-realloc shape) or
    /// through its pointee (`frees_param_pointees`). Without this the
    /// reassignment reads as an allocation dropped on the floor.
    ///
    /// Deliberately excludes bare `realloc(p, n)`: `p = realloc(p, n)` loses the
    /// original block when the call fails, which is a finding this rule is
    /// meant to make (see tests/fail/testcases_realloc_leak.c). A wrapper that
    /// hands the original pointer back on failure does not have that hole,
    /// which is what its summary records.
    fn call_releases_var(&self, expr: &Node, source: &str, var_name: &str) -> bool {
        let mut call = *expr;
        loop {
            let inner = match call.kind() {
                "parenthesized_expression" => call.named_child(0),
                "cast_expression" => call.child_by_field_name("value"),
                _ => None,
            };
            match inner {
                Some(i) => call = i,
                None => break,
            }
        }
        if call.kind() != "call_expression" {
            return false;
        }
        let Some(function) = call.child_by_field_name("function") else {
            return false;
        };
        let func_name = ast_utils::get_node_text_owned(&function, source);
        let Some(arguments) = call.child_by_field_name("arguments") else {
            return false;
        };
        let summary = self.function_summaries.get(&func_name);
        let mut param_idx = 0usize;
        for i in 0..arguments.child_count() {
            let Some(arg) = arguments.child(i) else {
                continue;
            };
            if arg.kind() == "," || arg.kind() == "(" || arg.kind() == ")" {
                continue;
            }
            if let Some((target, through_address_of)) = strip_call_argument(arg) {
                if ast_utils::get_node_text_owned(&target, source) == var_name {
                    if let Some(summary) = summary {
                        let frees = if through_address_of {
                            summary.frees_param_pointees.contains(&param_idx)
                        } else {
                            summary.frees_params.contains(&param_idx)
                        };
                        if frees {
                            return true;
                        }
                    }
                }
            }
            param_idx += 1;
        }
        false
    }

    fn process_return(&mut self, node: &Node, source: &str) {
        let return_pos = node.start_position();

        // If returning allocated memory, it escapes and shouldn't be considered a leak
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "identifier" {
                    let var_name = ast_utils::get_node_text_owned(&child, source);
                    if self.allocated_memory.contains_key(&var_name) {
                        self.escaped_memory.insert(var_name.clone());
                        // Also mark any field allocations belonging to this container as escaped
                        // e.g., if returning "person", mark "person->name" and "person->email" as escaped
                        let field_prefix = format!("{}->", var_name);
                        let fields_to_escape: Vec<String> = self
                            .allocated_memory
                            .keys()
                            .filter(|k| k.starts_with(&field_prefix))
                            .cloned()
                            .collect();
                        for field in fields_to_escape {
                            self.escaped_memory.insert(field);
                        }
                    }
                } else if self.is_allocation_call(&child, source) {
                    // Direct return of allocation is not a leak
                    // We don't track it since it escapes immediately
                }
            }
        }

        // Check for leaks at this return point
        for (var_name, alloc_info) in &self.allocated_memory {
            // Skip variables that are escaped, freed, null, static, or contain @ (leaked marker)
            if self.escaped_memory.contains(var_name)
                || self.freed_memory.contains_key(var_name)
                || self.null_variables.contains(var_name)
                || self.static_variables.contains(var_name)
                || var_name.contains('@')
            {
                continue;
            }

            // Memory allocated but not freed at this return point - leak!
            self.leak_violations.push(RuleViolation {
                rule_id: "MEM31-C".to_string(),
                severity: Severity::High,
                message: format!(
                    "Memory leak: '{}' allocated with '{}' is not freed before return",
                    var_name, alloc_info.alloc_type
                ),
                file_path: String::new(),
                line: return_pos.row + 1,
                column: return_pos.column + 1,
                suggestion: Some(format!("Free '{}' before this return statement", var_name)),
                ..Default::default()
            });
        }
    }

    /// Check if an if_statement's condition is a truthiness check (if (ptr))
    /// Returns the variable name - ptr is NOT NULL in true branch, NULL in else branch
    fn get_truthiness_check_variable(&self, if_node: &Node, source: &str) -> Option<String> {
        if let Some(condition) = if_node.child_by_field_name("condition") {
            // Handle parenthesized expression
            let cond = if condition.kind() == "parenthesized_expression" {
                condition.child(1)?
            } else {
                condition
            };

            // Plain identifier or field_expression as condition means truthiness check
            // if (ptr) { ... } else { /* ptr is NULL here */ }
            if matches!(
                cond.kind(),
                "identifier" | "field_expression" | "subscript_expression"
            ) {
                return Some(ast_utils::get_node_text_owned(&cond, source));
            }
        }
        None
    }

    /// Check if an if_statement's condition is a NULL check (var == NULL)
    /// Returns the variable name if it's a NULL check
    fn get_null_check_variable(&self, if_node: &Node, source: &str) -> Option<String> {
        // Look for the condition node
        if let Some(condition) = if_node.child_by_field_name("condition") {
            // Handle parenthesized expression
            let cond = if condition.kind() == "parenthesized_expression" {
                condition.child(1)?
            } else {
                condition
            };

            // Look for binary_expression with == NULL or != NULL
            if cond.kind() == "binary_expression" {
                let op_text = cond
                    .child_by_field_name("operator")
                    .map(|op| ast_utils::get_node_text_owned(&op, source))
                    .unwrap_or_default();

                // Only handle == (var is NULL in true branch)
                if op_text == "==" {
                    let left = cond.child_by_field_name("left")?;
                    let right = cond.child_by_field_name("right")?;

                    let left_text = ast_utils::get_node_text_owned(&left, source);
                    let right_text = ast_utils::get_node_text_owned(&right, source);

                    // Check for var == NULL or NULL == var
                    // Handle identifier, field_expression, and subscript_expression
                    if right_text == "NULL" || right_text == "0" || right.kind() == "null" {
                        if matches!(
                            left.kind(),
                            "identifier" | "field_expression" | "subscript_expression"
                        ) {
                            return Some(left_text);
                        }
                    }
                    if left_text == "NULL" || left_text == "0" || left.kind() == "null" {
                        if matches!(
                            right.kind(),
                            "identifier" | "field_expression" | "subscript_expression"
                        ) {
                            return Some(right_text);
                        }
                    }
                }
            }

            // Handle unary NOT: if (!ptr) means ptr is falsy (NULL) in true branch
            if cond.kind() == "unary_expression" {
                let op_text = cond
                    .child_by_field_name("operator")
                    .map(|op| ast_utils::get_node_text_owned(&op, source))
                    .unwrap_or_default();

                if op_text == "!" {
                    if let Some(arg) = cond.child_by_field_name("argument") {
                        if matches!(
                            arg.kind(),
                            "identifier" | "field_expression" | "subscript_expression"
                        ) {
                            return Some(ast_utils::get_node_text_owned(&arg, source));
                        }
                    }
                }
            }
        }
        None
    }

    /// Check if an if_statement's condition is a non-NULL check (var != NULL)
    /// Returns the variable name if it's a non-NULL check
    /// For `if (ptr != NULL) { ... } else { ... }`, ptr is NOT NULL in true branch, NULL in else
    fn get_non_null_check_variable(&self, if_node: &Node, source: &str) -> Option<String> {
        // Look for the condition node
        if let Some(condition) = if_node.child_by_field_name("condition") {
            // Handle parenthesized expression
            let cond = if condition.kind() == "parenthesized_expression" {
                condition.child(1)?
            } else {
                condition
            };

            // Look for binary_expression with != NULL
            if cond.kind() == "binary_expression" {
                let op_text = cond
                    .child_by_field_name("operator")
                    .map(|op| ast_utils::get_node_text_owned(&op, source))
                    .unwrap_or_default();

                // Handle != (var is NOT NULL in true branch, NULL in else branch)
                if op_text == "!=" {
                    let left = cond.child_by_field_name("left")?;
                    let right = cond.child_by_field_name("right")?;

                    let left_text = ast_utils::get_node_text_owned(&left, source);
                    let right_text = ast_utils::get_node_text_owned(&right, source);

                    // Check for var != NULL or NULL != var
                    if right_text == "NULL" || right_text == "0" || right.kind() == "null" {
                        if matches!(
                            left.kind(),
                            "identifier" | "field_expression" | "subscript_expression"
                        ) {
                            return Some(left_text);
                        }
                    }
                    if left_text == "NULL" || left_text == "0" || left.kind() == "null" {
                        if matches!(
                            right.kind(),
                            "identifier" | "field_expression" | "subscript_expression"
                        ) {
                            return Some(right_text);
                        }
                    }
                }
            }
        }
        None
    }

    /// Check if a function name suggests it's a deallocation function
    fn is_deallocation_call(&self, func_name: &str) -> bool {
        ast_utils::is_deallocation_call_name(func_name)
    }

    fn is_allocation_call(&self, node: &Node, source: &str) -> bool {
        // Handle cast expressions like (char *)malloc(...)
        if node.kind() == "cast_expression" {
            if let Some(value) = node.child_by_field_name("value") {
                return self.is_allocation_call(&value, source);
            }
        }

        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = ast_utils::get_node_text_owned(&function, source);

                // Standard allocation functions
                if call_roles::is_allocator_call(&func_name) {
                    return true;
                }

                // Heuristic: function names that suggest allocation
                let lower_name = func_name.to_lowercase();
                if lower_name.starts_with("create_")
                    || lower_name.starts_with("alloc_")
                    || lower_name.starts_with("new_")
                    || lower_name.starts_with("make_")
                    || lower_name.starts_with("build_")
                    || lower_name.ends_with("_alloc")
                    || lower_name.ends_with("_create")
                    || lower_name.ends_with("_new")
                    || lower_name.ends_with("_dup")
                {
                    return true;
                }

                // Inter-procedural: a user-defined wrapper whose body was
                // seen to malloc/calloc/realloc/aligned_alloc and return the
                // result (FunctionSummary.returns_allocation) is just as much
                // a fresh allocation as the literal/heuristic cases above.
                // Without this, reassigning through such a wrapper after a
                // free (e.g. `txt = octet_string_str(hash);`) never clears
                // freed_memory, so the next free(txt) is flagged as a false
                // double-free against stale state (task: MEM31-C wrapper
                // reassignment).
                if self
                    .function_summaries
                    .get(&func_name)
                    .is_some_and(|summary| summary.returns_allocation)
                {
                    return true;
                }
            }
        }
        false
    }

    fn get_allocation_type(&self, node: &Node, source: &str) -> String {
        // Handle cast expressions like (char *)malloc(...)
        if node.kind() == "cast_expression" {
            if let Some(value) = node.child_by_field_name("value") {
                return self.get_allocation_type(&value, source);
            }
        }

        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                return ast_utils::get_node_text_owned(&function, source);
            }
        }
        "unknown".to_string()
    }

    /// Resolve a declarator's bound identifier, unwrapping arbitrarily-nested
    /// pointer/array/function/parenthesized declarators (see
    /// `ast_utils::get_identifier_from_declarator`). Returns `"unknown"`
    /// (this rule's existing not-found sentinel) instead of an empty string.
    fn get_variable_name(&self, declarator: &Node, source: &str) -> String {
        match ast_utils::get_identifier_from_declarator(declarator, source) {
            name if name.is_empty() => "unknown".to_string(),
            name => name,
        }
    }

    fn detect_leaks(&self, violations: &mut Vec<RuleViolation>) {
        for (var_name, alloc_info) in &self.allocated_memory {
            if !self.freed_memory.contains_key(var_name)
                && !self.escaped_memory.contains(var_name)
                && !self.static_variables.contains(var_name)
            {
                violations.push(RuleViolation {
                    rule_id: "MEM31-C".to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Memory allocated with '{}' for variable '{}' is not freed",
                        alloc_info.alloc_type, var_name
                    ),
                    file_path: String::new(),
                    line: alloc_info.line,
                    column: alloc_info.column,
                    suggestion: Some(format!(
                        "Add 'free({})' before the variable goes out of scope",
                        var_name
                    )),
                    ..Default::default()
                });
            }
        }

        // Check for mismatched loop allocation/free patterns
        for (array_base, (alloc_cond, free_cond)) in &self.loop_array_patterns {
            if let (Some(alloc), Some(free)) = (alloc_cond, free_cond) {
                if alloc != free {
                    // Extract the numeric bounds if possible for a clearer message
                    violations.push(RuleViolation {
                        rule_id: "MEM31-C".to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Array '{}' elements allocated in loop with condition '{}' but freed with different condition '{}' - some elements may leak",
                            array_base, alloc, free
                        ),
                        file_path: String::new(),
                        line: 1,
                        column: 1,
                        suggestion: Some(format!(
                            "Ensure all elements of '{}' are freed with the same loop bounds used for allocation",
                            array_base
                        )),
                        ..Default::default()
                    });
                }
            } else if alloc_cond.is_some() && free_cond.is_none() {
                // Allocated in loop but not freed in any loop
                violations.push(RuleViolation {
                    rule_id: "MEM31-C".to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Array '{}' elements allocated in loop but not freed in a matching loop - elements may leak",
                        array_base
                    ),
                    file_path: String::new(),
                    line: 1,
                    column: 1,
                    suggestion: Some(format!(
                        "Free all elements of '{}' in a loop with the same bounds",
                        array_base
                    )),
                    ..Default::default()
                });
            }
        }
    }

    /// True if `node` contains a statement that ends the enclosing branch.
    ///
    /// A `return` is the obvious one. A call to a function that never returns
    /// -- `exit()`, `abort()`, a `_Noreturn`/`__attribute__((noreturn))`
    /// error handler -- ends the branch just as firmly, so a `free()` before
    /// it cannot reach code textually after the `if`. Missing that reported a
    /// double free on four pure-ftpd sites whose early-error branch calls a
    /// process-terminating helper before the shared cleanup runs (task 1076).
    fn block_has_return(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            n.kind() == "return_statement"
                || crate::analyze::noreturn::is_noreturn_call_statement(
                    &n,
                    source,
                    self.noreturn_names,
                )
        })
        .is_some()
    }
}

/// Resolve the declared type of `left`'s field when `left`'s base is a cast
/// macro rather than a variable.
///
/// seL4 writes `REPLY_PTR(next_ptr)->replyPrev = call_stack_new(0, false)`,
/// where `#define REPLY_PTR(r) ((reply_t *) (r))`.
/// `resolve_field_expression_type` resolves a base through the declared-type
/// map, which is keyed on variable names, so a `call_expression` base has
/// nothing to look up. The field is the same value-typed `call_stack_t` the
/// guard already suppresses two lines further down on `reply->replyPrev`; only
/// how the base is spelled differs.
///
/// Expanding the invocation against the project's own macro table is the
/// name-independent route CLAUDE.md requires over a spelling heuristic: the
/// cast in the expansion is the type declaration the code actually gives for
/// that expression, and it comes from the project's `#define`, not from
/// anything this rule assumes about the name.
fn resolve_macro_based_field_type(
    left: &Node,
    source: &str,
    struct_field_types: &HashMap<String, HashMap<String, String>>,
    struct_typedef_aliases: &HashMap<String, String>,
    function_macros: &HashMap<String, FunctionMacro>,
) -> Option<String> {
    let field_node = left.child_by_field_name("field")?;
    let field_name = ast_utils::get_node_text_owned(&field_node, source);
    let argument = left.child_by_field_name("argument")?;
    let cast_type = macro_cast_pointer_type(&argument, source, function_macros)?;
    let struct_name = ast_utils::extract_struct_name_from_type(&cast_type)?;
    // Same tag hop as the declared-variable path: fields file under the TAG.
    let tag = struct_typedef_aliases
        .get(struct_name)
        .map(String::as_str)
        .unwrap_or(struct_name);
    struct_field_types.get(tag)?.get(&field_name).cloned()
}

/// The pointer type a macro invocation casts to, or `None` if `base` is not a
/// call of a known function-like macro that expands to a leading pointer cast.
fn macro_cast_pointer_type(
    base: &Node,
    source: &str,
    function_macros: &HashMap<String, FunctionMacro>,
) -> Option<String> {
    if base.kind() != "call_expression" || function_macros.is_empty() {
        return None;
    }
    let function = base.child_by_field_name("function")?;
    if function.kind() != "identifier" {
        return None;
    }
    let name = ast_utils::get_node_text_owned(&function, source);
    let arguments = base.child_by_field_name("arguments")?;
    let args: Vec<String> = (0..arguments.named_child_count())
        .filter_map(|i| arguments.named_child(i))
        .map(|a| ast_utils::get_node_text_owned(&a, source))
        .collect();
    let expanded = macro_expand::expand_invocation(function_macros, &name, &args)?;
    leading_pointer_cast_type(&expanded)
}

/// The type of a leading pointer cast in `text`, after peeling redundant outer
/// parentheses: `((reply_t *) (r))` yields `reply_t *`.
///
/// Only a POINTER cast counts, and only one that has something after it to
/// apply to. `MACRO(x)->field` can only be a field access if the expansion
/// produced something dereferenceable, so a bare `(reply_t *)` with nothing
/// following it, or a non-pointer cast, means the expansion is not the base
/// this is trying to type and guessing further would be worse than declining.
fn leading_pointer_cast_type(text: &str) -> Option<String> {
    let mut s = text.trim();
    while let Some(inner) = strip_redundant_parens(s) {
        s = inner;
    }
    let close = matching_paren(s)?;
    let cast = s[1..close].trim();
    if s[close + 1..].trim().is_empty() || !cast.ends_with('*') {
        return None;
    }
    Some(cast.to_string())
}

/// `s` with one wrapping parenthesis pair removed, if `s` is entirely
/// parenthesised (`(a)(b)` is not, and is returned as `None`).
fn strip_redundant_parens(s: &str) -> Option<&str> {
    if matching_paren(s)? + 1 != s.len() {
        return None;
    }
    Some(s[1..s.len() - 1].trim())
}

/// Byte offset of the `)` matching the `(` that `s` must start with.
fn matching_paren(s: &str) -> Option<usize> {
    if !s.starts_with('(') {
        return None;
    }
    let mut depth = 0usize;
    for (i, b) in s.bytes().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Names used through a pointer-shaped operation in `node`: `p->f`, `*p`,
/// `p[i]`, or a `p == NULL`/`p != NULL` comparison. Any one of these is
/// evidence that `p` really is a pointer even when its declarator carries no
/// `*` (a pointer typedef), which is what takes it back out of
/// `collect_value_only_locals`' candidate set.
///
/// `&p` is deliberately not evidence: taking the address of a plain value
/// local is ordinary C and says nothing about `p`'s own type.
/// The field-expression texts `node` uses in a pointer-shaped way: base of
/// `->`, base of a subscript, operand of a unary `*`, or either side of a
/// `==`/`!=` against `NULL`.
///
/// The field-target counterpart of [`pointer_shaped_operand_names`], which
/// yields bare identifiers only. Kept separate rather than widened, because
/// that function also feeds `collect_value_only_locals` -- whose candidate set
/// holds nothing but declared identifiers, so adding field texts there would
/// only cost a scan.
///
/// A `.` base is deliberately not evidence: `a.b` says nothing about whether
/// `a` is a pointer, and by the same token it says nothing about `b`.
fn pointer_shaped_field_texts(node: &Node, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut push_field = |n: Option<Node>| {
        if let Some(n) = n {
            if n.kind() == "field_expression" {
                names.push(ast_utils::get_node_text_owned(&n, source));
            }
        }
    };

    match node.kind() {
        "field_expression" => {
            let is_arrow = node
                .child_by_field_name("operator")
                .map(|op| ast_utils::get_node_text(&op, source) == "->")
                .unwrap_or(false);
            if is_arrow {
                push_field(node.child_by_field_name("argument"));
            }
        }
        "pointer_expression" => {
            let is_deref = node
                .child_by_field_name("operator")
                .map(|op| ast_utils::get_node_text(&op, source) == "*")
                .unwrap_or(false);
            if is_deref {
                push_field(node.child_by_field_name("argument"));
            }
        }
        "subscript_expression" => {
            push_field(node.child_by_field_name("argument"));
        }
        "binary_expression" => {
            let op = node
                .child_by_field_name("operator")
                .map(|o| ast_utils::get_node_text_owned(&o, source))
                .unwrap_or_default();
            if op == "==" || op == "!=" {
                let left = node.child_by_field_name("left");
                let right = node.child_by_field_name("right");
                for (field, other) in [(left, right), (right, left)] {
                    let (Some(field), Some(other)) = (field, other) else {
                        continue;
                    };
                    if ast_utils::get_node_text(&other, source) == "NULL" {
                        push_field(Some(field));
                    }
                }
            }
        }
        _ => {}
    }
    names
}

fn pointer_shaped_operand_names(node: &Node, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    match node.kind() {
        "field_expression" => {
            // Only `->` implies the base is a pointer; `.` does not.
            let is_arrow = node
                .child_by_field_name("operator")
                .map(|op| ast_utils::get_node_text(&op, source) == "->")
                .unwrap_or(false);
            if is_arrow {
                if let Some(arg) = node.child_by_field_name("argument") {
                    if arg.kind() == "identifier" {
                        names.push(ast_utils::get_node_text_owned(&arg, source));
                    }
                }
            }
        }
        "pointer_expression" => {
            let is_deref = node
                .child_by_field_name("operator")
                .map(|op| ast_utils::get_node_text(&op, source) == "*")
                .unwrap_or(false);
            if is_deref {
                if let Some(arg) = node.child_by_field_name("argument") {
                    if arg.kind() == "identifier" {
                        names.push(ast_utils::get_node_text_owned(&arg, source));
                    }
                }
            }
        }
        "subscript_expression" => {
            if let Some(arg) = node.child_by_field_name("argument") {
                if arg.kind() == "identifier" {
                    names.push(ast_utils::get_node_text_owned(&arg, source));
                }
            }
        }
        "binary_expression" => {
            let op = node
                .child_by_field_name("operator")
                .map(|o| ast_utils::get_node_text_owned(&o, source))
                .unwrap_or_default();
            if op == "==" || op == "!=" {
                let left = node.child_by_field_name("left");
                let right = node.child_by_field_name("right");
                for (ident, other) in [(left, right), (right, left)] {
                    let (Some(ident), Some(other)) = (ident, other) else {
                        continue;
                    };
                    if ident.kind() == "identifier"
                        && ast_utils::get_node_text(&other, source) == "NULL"
                    {
                        names.push(ast_utils::get_node_text_owned(&ident, source));
                    }
                }
            }
        }
        _ => {}
    }
    names
}
