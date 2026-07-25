//! Initialization-state forward dataflow analysis using the CFG.
//!
//! Tracks whether local variables have been initialized at every point in a
//! function. Used by EXP33-C to detect reads of uninitialized memory with
//! proper flow sensitivity through branches, loops, and early returns.

use super::cfg::{BasicBlock, BlockId, CfgEdge, FunctionCfg};
use super::const_eval;
use super::dataflow::find_node_at_range;
use std::collections::{HashMap, HashSet, VecDeque};
use tree_sitter::Node;

// ---------------------------------------------------------------------------
// Init lattice
// ---------------------------------------------------------------------------

/// Initialization state for a single variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitState {
    /// Definitely uninitialized on all reaching paths.
    Uninitialized,
    /// Initialized on some paths but not all.
    MaybeUninitialized,
    /// Definitely initialized on all reaching paths.
    Initialized,
    /// Allocated via malloc/alloca — pointer is set but content is uninitialized.
    MallocUninitialized,
    /// Allocated and content written (calloc, memset after malloc, etc.).
    MallocInitialized,
}

impl InitState {
    /// Lattice join: merge two states from converging paths.
    pub fn join(self, other: InitState) -> InitState {
        use InitState::*;
        if self == other {
            return self;
        }
        match (self, other) {
            // MallocUninitialized + MallocInitialized → MallocInitialized
            // If content was initialized on any path, treat as initialized.
            // Catches loop-based initialization patterns (alloc then loop-write).
            (MallocUninitialized, MallocInitialized) | (MallocInitialized, MallocUninitialized) => {
                MallocInitialized
            }
            // Initialized + Uninitialized → MaybeUninitialized
            (Initialized, Uninitialized) | (Uninitialized, Initialized) => MaybeUninitialized,
            // Initialized + Malloc* → Initialized for the pointer itself.
            // The pointer is assigned on all paths; only content differs.
            (Initialized, MallocUninitialized)
            | (MallocUninitialized, Initialized)
            | (Initialized, MallocInitialized)
            | (MallocInitialized, Initialized) => Initialized,
            // MaybeUninitialized absorbs everything
            (MaybeUninitialized, _) | (_, MaybeUninitialized) => MaybeUninitialized,
            // Uninitialized + Malloc* → MaybeUninitialized
            _ => MaybeUninitialized,
        }
    }

    /// Returns true if a read at this state is potentially unsafe.
    pub fn is_unsafe(self) -> bool {
        matches!(
            self,
            InitState::Uninitialized | InitState::MaybeUninitialized
        )
    }

    /// Returns true if content access (dereference/subscript) is unsafe.
    pub fn is_content_unsafe(self) -> bool {
        matches!(
            self,
            InitState::Uninitialized
                | InitState::MaybeUninitialized
                | InitState::MallocUninitialized
        )
    }
}

// ---------------------------------------------------------------------------
// Variable metadata
// ---------------------------------------------------------------------------

/// Per-variable info tracked alongside InitState.
#[derive(Debug, Clone, PartialEq)]
pub struct VarInfo {
    pub state: InitState,
    pub is_unsigned_char: bool,
    pub is_array: bool,
    pub is_static: bool,
    /// True for `char` or `wchar_t` arrays. Used to distinguish char buffers
    /// (CWE-665: strcat reads from uninit buffer) from int/double/struct arrays
    /// (CWE-457: content read via subscript) for array-decay suppression logic.
    pub is_char_type: bool,
    /// Element count from `malloc(N * sizeof(T))` / `ALLOCA(N * sizeof(T))`.
    /// Used to detect partial initialization loops.
    pub allocation_count: Option<usize>,
}

impl VarInfo {
    pub fn new(state: InitState) -> Self {
        Self {
            state,
            is_unsigned_char: false,
            is_array: false,
            is_static: false,
            is_char_type: false,
            allocation_count: None,
        }
    }
}

/// State map: variable name -> VarInfo.
pub type InitStateMap = HashMap<String, VarInfo>;

/// Join two state maps (union of keys, lattice join per key).
/// Variables present in one map but not the other are copied as-is from
/// the side that has them. This handles loop-local variables that are
/// only declared inside one branch.
fn join_states(a: &InitStateMap, b: &InitStateMap) -> InitStateMap {
    let mut result = a.clone();
    for (var, info_b) in b {
        let entry = result.entry(var.clone()).or_insert_with(|| info_b.clone());
        if entry.state != info_b.state {
            entry.state = entry.state.join(info_b.state);
        }
    }
    result
}

/// Join with goto-awareness: variables present in `normal_path` but absent
/// in `goto_path` are treated as Uninitialized on the goto path (the goto
/// skipped the declaration).
fn join_with_goto(normal_path: &InitStateMap, goto_path: &InitStateMap) -> InitStateMap {
    let mut result = HashMap::new();
    let all_keys: HashSet<&String> = normal_path.keys().chain(goto_path.keys()).collect();
    for var in all_keys {
        match (normal_path.get(var), goto_path.get(var)) {
            (Some(ia), Some(ib)) => {
                let mut merged = ia.clone();
                merged.state = ia.state.join(ib.state);
                result.insert(var.clone(), merged);
            }
            (Some(ia), None) => {
                // Variable declared on normal path, skipped by goto
                let mut merged = ia.clone();
                merged.state = ia.state.join(InitState::Uninitialized);
                result.insert(var.clone(), merged);
            }
            (None, Some(ib)) => {
                result.insert(var.clone(), ib.clone());
            }
            (None, None) => unreachable!(),
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Analysis result
// ---------------------------------------------------------------------------

/// Result of init-state analysis for one function.
#[allow(dead_code)]
pub struct InitAnalysisResult {
    pub block_entry_states: HashMap<BlockId, InitStateMap>,
    pub block_exit_states: HashMap<BlockId, InitStateMap>,
    /// Variables tracked during analysis.
    pub tracked_vars: HashSet<String>,
}

// ---------------------------------------------------------------------------
// Known function behavior
// ---------------------------------------------------------------------------

/// Common C library initializer suffixes. A function whose name ends with one
/// of these (e.g., `os_memset`, `wp_memcpy`) is treated as an initializing function
/// with the same argument semantics as the base function.
const INITIALIZER_SUFFIXES: &[&str] = &[
    "memset", "memcpy", "memmove", "strcpy", "strncpy", "sprintf", "snprintf", "bzero", "strcat",
    "strncat",
];

/// Check if `func_name` is a known initializing function (exact match or suffix wrapper).
/// Returns the canonical base name if matched, or None.
pub fn match_initializing_function(func_name: &str) -> Option<&'static str> {
    if let Some(&entry) = INITIALIZING_FUNCTIONS.iter().find(|&&e| e == func_name) {
        return Some(entry);
    }
    // Suffix match: os_memset → memset, wp_memcpy → memcpy, etc.
    INITIALIZER_SUFFIXES
        .iter()
        .find(|&&suffix| func_name.len() > suffix.len() && func_name.ends_with(suffix))
        .copied()
}

/// Functions that initialize their output arguments.
pub const INITIALIZING_FUNCTIONS: &[&str] = &[
    "memset",
    "memcpy",
    "memmove",
    "strcpy",
    "strncpy",
    "sprintf",
    "snprintf",
    "fgets",
    "fread",
    "read",
    "recv",
    "scanf",
    "fscanf",
    "sscanf",
    "gets",
    "bzero",
    "strcat",
    "strncat",
    // POSIX/system functions that initialize via output pointers
    "gettimeofday",
    "getaddrinfo",
    "stat",
    "fstat",
    "lstat",
    "getrusage",
    "getsockname",
    "getpeername",
    "clock_gettime",
    "pthread_attr_init",
    "pthread_mutex_init",
    "pthread_cond_init",
    "regcomp",
    "regexec",
    "sigaction",
    "sigemptyset",
    "sigfillset",
    "mbrlen",
    "mbrtowc",
    "mbsrtowcs",
    "wcrtomb",
    "wcsrtombs",
];

/// Get which argument indices are output (initialized) for known functions.
pub fn get_output_arg_indices(func_name: &str) -> Vec<usize> {
    match func_name {
        "memset" | "memcpy" | "memmove" | "strcpy" | "strncpy" | "sprintf" | "snprintf"
        | "strcat" | "strncat" | "bzero" => vec![0],
        "fgets" | "gets" => vec![0],
        "fread" | "read" | "recv" => vec![0],
        "scanf" | "fscanf" | "sscanf" => vec![],
        "gettimeofday" => vec![0],
        "getaddrinfo" => vec![3],
        "stat" | "fstat" | "lstat" => vec![1],
        "getrusage" => vec![1],
        "getsockname" | "getpeername" => vec![1, 2],
        "clock_gettime" => vec![1],
        "pthread_attr_init" | "pthread_mutex_init" | "pthread_cond_init" => vec![0],
        "sigaction" => vec![2],
        "sigemptyset" | "sigfillset" => vec![0],
        "regcomp" => vec![0],
        "mbrlen" | "mbrtowc" | "mbsrtowcs" | "wcrtomb" | "wcsrtombs" => vec![],
        "regexec" => vec![],
        _ => vec![0], // Default: first arg is output
    }
}

/// Functions known to only READ from their pointer arguments (not initialize).
pub fn is_non_initializing_function(func_name: &str) -> bool {
    matches!(
        func_name,
        "mbrlen"
            | "mbrtowc"
            | "mbsrtowcs"
            | "wcrtomb"
            | "wcsrtombs"
            | "regexec"
            | "memcmp"
            | "strcmp"
            | "strncmp"
            | "wmemcmp"
            | "wcscmp"
            | "wcsncmp"
            | "printf"
            | "fprintf"
            | "vprintf"
            | "vfprintf"
            | "puts"
            | "fputs"
            | "putchar"
            | "fputc"
            | "strlen"
            | "wcslen"
            | "strchr"
            | "strrchr"
            | "strstr"
            | "strpbrk"
            | "crc32"
            | "md5"
            | "sha1"
            | "sha256"
            | "fwrite"
            | "write"
            | "send"
            | "sendto"
    )
}
// Iterator/find/output macro semantics now live in
// `crate::analyze::macro_semantics` (positional roles), replacing the former
// first-arg-only FOR_EACH_MACROS list.

// ---------------------------------------------------------------------------
// Analysis configuration
// ---------------------------------------------------------------------------

/// Configuration for init-state analysis, carrying interprocedural info.
#[derive(Default)]
pub struct InitAnalysisConfig {
    /// Functions with pointer params that are only conditionally initialized.
    /// Maps function name → set of parameter indices where `*param = ...` only
    /// appears inside conditionals. Other params are assumed initialized normally.
    pub conditionally_init_fns: HashMap<String, HashSet<usize>>,
    /// Functions that wrap realloc (return uninitialized new portion).
    pub realloc_wrapper_fns: HashSet<String>,
    /// Cross-file functions that dereference pointer params without modifying them.
    /// Maps function name → set of param indices that are read-only dereferenced.
    /// When `&var` is passed at these positions, var should NOT be marked initialized.
    pub read_only_deref_fns: HashMap<String, HashSet<usize>>,
    /// File-scope constants (static const and static variables with known init values).
    /// Used for dead-branch elimination when conditions evaluate to known constants.
    pub file_scope_constants: HashMap<String, i64>,
    /// Output-parameter indices for invoked function-like macros (from the
    /// macro-expansion engine, `macro_expand::macro_output_param_indices`). When
    /// a macro at one of these positions takes a bare identifier, the macro
    /// *writes* that variable (e.g. curl's `CF_DATA_SAVE(save, …)` assigns
    /// `save`), so it becomes Initialized — clearing "used uninitialized" FPs on
    /// macro output arguments. Keyed by macro name; only invoked macros present.
    pub macro_output_params: HashMap<String, Vec<usize>>,
    /// Output-parameter indices for cross-file functions, computed from the
    /// prescan's `FunctionSummary::modifies_params` (task 195 follow-on to
    /// task 319: un-blinding `#ifdef`-wrapped code to the CFG exposed how many
    /// real, in-repo functions like `erp_parse_tlvs(pos, end, &tlvs, ...)`
    /// write through a non-stdlib, non-macro pointer param that
    /// `get_output_arg_indices`'s hardcoded stdlib table has no entry for).
    /// When `&var` is passed at one of these positions, var is Initialized —
    /// same effect as `macro_output_params`, but sourced from an actual
    /// function body rather than a macro expansion.
    pub cross_file_output_params: HashMap<String, HashSet<usize>>,
}

// ---------------------------------------------------------------------------
// Transfer function
// ---------------------------------------------------------------------------

/// Apply the transfer function: simulate all statements in a basic block,
/// updating the init-state map.
fn apply_transfer(
    block: &BasicBlock,
    entry_state: &InitStateMap,
    body: &Node,
    source: &str,
    tracked_vars: &mut HashSet<String>,
    config: &InitAnalysisConfig,
) -> InitStateMap {
    let mut state = entry_state.clone();
    for &(start, end) in &block.statements {
        if let Some(stmt_node) = find_node_at_range(body, start, end) {
            process_statement(&stmt_node, source, &mut state, tracked_vars, config);
        }
    }
    state
}

/// Process a single statement for initialization effects.
fn process_statement(
    node: &Node,
    source: &str,
    state: &mut InitStateMap,
    tracked_vars: &mut HashSet<String>,
    config: &InitAnalysisConfig,
) {
    match node.kind() {
        "declaration" => process_declaration(node, source, state, tracked_vars, config),
        "expression_statement" => {
            // Unwrap to the actual expression
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() != ";" {
                        process_expression(&child, source, state, tracked_vars, config);
                    }
                }
            }
        }
        "assignment_expression" | "update_expression" | "call_expression" | "comma_expression" => {
            process_expression(node, source, state, tracked_vars, config);
        }
        // For-loop initializer declarations appear directly as nodes
        "init_declarator" => {
            // Part of a declaration processed at the statement level
        }
        // GNU inline assembly: `asm("..." : "=r"(var) : ...)`.
        // Output operands (first `:` list) write into their `value` field
        // identifier, initializing those variables from the caller's
        // perspective. Mark all output-operand identifiers as Initialized
        // so reads after the asm statement do not falsely flag.
        "gnu_asm_expression" => {
            process_gnu_asm(node, source, state);
        }
        _ => {
            // Recursively search for init-relevant expressions in nested nodes
            // (e.g., call inside binary_expression inside parenthesized_expression)
            find_and_process_init_expressions(node, source, state, tracked_vars, config);
        }
    }
}

/// Process a declaration for initialization tracking.
fn process_declaration(
    node: &Node,
    source: &str,
    state: &mut InitStateMap,
    tracked_vars: &mut HashSet<String>,
    config: &InitAnalysisConfig,
) {
    // Determine type properties
    let type_text = extract_type_text(node, source);
    let is_unsigned_char = type_text.contains("unsigned char")
        || type_text.contains("uint8_t")
        || type_text.contains("BYTE");
    let is_char_type =
        (type_text.contains("char") || type_text.contains("wchar_t")) && !is_unsigned_char;
    let is_static = type_text.contains("static") || type_text.contains("_Thread_local");

    // Process each declarator
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "init_declarator" => {
                    let var_name = get_declarator_name(&child, source);
                    if var_name.is_empty() {
                        continue;
                    }
                    tracked_vars.insert(var_name.clone());

                    // Has initializer — determine what kind
                    if let Some(value) = child.child_by_field_name("value") {
                        let init_state = classify_initializer(&value, source, config);
                        let is_array = is_array_declarator(&child);
                        let mut info = VarInfo::new(init_state);
                        info.is_unsigned_char = is_unsigned_char;
                        info.is_char_type = is_char_type;
                        info.is_array = is_array;
                        info.is_static = is_static;
                        if matches!(init_state, InitState::MallocUninitialized) {
                            info.allocation_count = extract_allocation_count(&value, source);
                        }
                        state.insert(var_name, info);
                    }
                }
                "identifier" => {
                    // Plain declaration without initializer: `int x;`
                    let var_name = get_text(node, &child, source);
                    if !var_name.is_empty() && !is_type_keyword(&var_name) {
                        tracked_vars.insert(var_name.clone());
                        let init_state = if is_static {
                            // Static/thread-local vars are zero-initialized by the C standard,
                            // but EXP33-C recommends explicit initialization. Track as
                            // Uninitialized with is_static=true for softer reporting.
                            InitState::Uninitialized
                        } else {
                            InitState::Uninitialized
                        };
                        let is_array = false;
                        let mut info = VarInfo::new(init_state);
                        info.is_unsigned_char = is_unsigned_char;
                        info.is_char_type = is_char_type;
                        info.is_array = is_array;
                        info.is_static = is_static;
                        state.insert(var_name, info);
                    }
                }
                "pointer_declarator" | "array_declarator" => {
                    // `int *p;` or `int arr[10];` without initializer
                    let var_name = get_declarator_name(&child, source);
                    if !var_name.is_empty() {
                        tracked_vars.insert(var_name.clone());
                        let init_state = InitState::Uninitialized;
                        let is_array = child.kind() == "array_declarator";
                        let mut info = VarInfo::new(init_state);
                        info.is_unsigned_char = is_unsigned_char;
                        info.is_char_type = is_char_type;
                        info.is_array = is_array;
                        info.is_static = is_static;
                        // Track declared array size (e.g., int arr[10]) so that
                        // array-to-pointer decay propagation can preserve the count
                        // for partial-init detection (MallocUninitialized flow).
                        if is_array {
                            if let Some(size_node) = child.child_by_field_name("size") {
                                let empty: HashMap<String, i64> = HashMap::new();
                                if let Some(sz) =
                                    const_eval::try_evaluate_expr(&size_node, source, &empty)
                                {
                                    if sz > 0 {
                                        info.allocation_count = Some(sz as usize);
                                    }
                                }
                            }
                        }
                        state.insert(var_name, info);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Classify an initializer expression to determine init state.
fn classify_initializer(value: &Node, source: &str, config: &InitAnalysisConfig) -> InitState {
    let text = value.utf8_text(source.as_bytes()).unwrap_or("");

    // Check for malloc/calloc/alloca patterns
    if value.kind() == "call_expression" {
        if let Some(func) = value.child_by_field_name("function") {
            let func_name = func.utf8_text(source.as_bytes()).unwrap_or("");
            match func_name {
                "calloc" => return InitState::MallocInitialized,
                "malloc" | "alloca" | "ALLOCA" => return InitState::MallocUninitialized,
                "realloc" => return InitState::MallocUninitialized,
                _ => {
                    // Check realloc wrapper functions (identified by pre-scan)
                    if config.realloc_wrapper_fns.contains(func_name) {
                        return InitState::MallocUninitialized;
                    }
                }
            }
        }
    }

    // Cast expressions: (type *)malloc(...)
    if value.kind() == "cast_expression" {
        for i in 0..value.child_count() {
            if let Some(child) = value.child(i) {
                if child.kind() == "call_expression" {
                    return classify_initializer(&child, source, config);
                }
            }
        }
    }

    // Check for text-based malloc patterns (macro wrappers)
    if text.contains("malloc(") || text.contains("alloca(") || text.contains("ALLOCA(") {
        return InitState::MallocUninitialized;
    }
    if text.contains("calloc(") || text.contains("zalloc(") {
        return InitState::MallocInitialized;
    }
    if text.contains("realloc(") {
        return InitState::MallocUninitialized;
    }

    InitState::Initialized
}

/// Extract element count from `malloc(N * sizeof(T))` / `ALLOCA(N * sizeof(T))`.
/// Returns the number of elements allocated (N), or None if not determinable.
fn extract_allocation_count(value: &Node, source: &str) -> Option<usize> {
    // Unwrap cast expressions: (int *)ALLOCA(...)
    let inner = if value.kind() == "cast_expression" {
        value.child_by_field_name("value")?
    } else {
        *value
    };

    if inner.kind() != "call_expression" {
        // Text-based fallback for macro wrappers
        let text = inner.utf8_text(source.as_bytes()).ok()?;
        return extract_allocation_count_from_text(text);
    }

    let func = inner.child_by_field_name("function")?;
    let func_name = func.utf8_text(source.as_bytes()).ok()?;
    if !matches!(func_name, "malloc" | "alloca" | "ALLOCA" | "realloc") {
        return None;
    }

    let args = inner.child_by_field_name("arguments")?;
    // Get the first real argument (skip parentheses and commas)
    let arg = {
        let mut found = None;
        for i in 0..args.child_count() {
            if let Some(c) = args.child(i) {
                if c.kind() != "(" && c.kind() != ")" && c.kind() != "," {
                    found = Some(c);
                    break;
                }
            }
        }
        found?
    };

    // Pattern: N * sizeof(T) — extract N
    if arg.kind() == "binary_expression" {
        let op = find_operator_text(&arg, source);
        if op == "*" {
            let left = arg.child_by_field_name("left")?;
            let right = arg.child_by_field_name("right")?;
            let macros: HashMap<String, i64> = HashMap::new();
            // If left is sizeof, evaluate right (and vice versa)
            if left.kind() == "sizeof_expression" {
                let val = const_eval::try_evaluate_expr(&right, source, &macros)?;
                return if val > 0 { Some(val as usize) } else { None };
            }
            if right.kind() == "sizeof_expression" {
                let val = const_eval::try_evaluate_expr(&left, source, &macros)?;
                return if val > 0 { Some(val as usize) } else { None };
            }
        }
    }
    None
}

/// Extract allocation count from text representation (for macro wrappers).
fn extract_allocation_count_from_text(text: &str) -> Option<usize> {
    // Match patterns like ALLOCA(10*sizeof(int)) or malloc(10 * sizeof(int))
    let inner = if let Some(start) = text.find('(') {
        // Find the matching argument
        &text[start + 1..text.rfind(')')?]
    } else {
        return None;
    };
    // Look for N*sizeof or N * sizeof
    if let Some(sizeof_pos) = inner.find("sizeof") {
        let before = inner[..sizeof_pos].trim().trim_end_matches('*').trim();
        let macros: HashMap<String, i64> = HashMap::new();
        // Try to parse the count as a simple integer or expression
        if let Ok(val) = before.parse::<i64>() {
            return if val > 0 { Some(val as usize) } else { None };
        }
        // Try parenthesized expression like (10/2)
        let _ = macros; // text-based fallback doesn't use AST evaluation
    }
    None
}

/// Find the operator text in a binary_expression.
fn find_operator_text<'a>(node: &Node, source: &'a str) -> &'a str {
    for i in 0..node.child_count() {
        if let Some(c) = node.child(i) {
            let k = c.kind();
            if matches!(
                k,
                "+" | "-" | "*" | "/" | "%" | "==" | "!=" | "<" | ">" | "<=" | ">="
            ) {
                return c.utf8_text(source.as_bytes()).unwrap_or("");
            }
        }
    }
    ""
}

/// Check if a subscript write should keep MallocUninitialized (partial init).
/// Returns true if the write is inside a for-loop whose bound is less than
/// the variable's allocation count.
fn is_partial_init_write(alloc_count: usize, node: &Node, source: &str) -> bool {
    // Walk up AST to find enclosing for_statement
    let mut current = node.parent();
    while let Some(n) = current {
        if n.kind() == "for_statement" {
            // Extract the condition (second child after the first ";")
            if let Some(condition) = n.child_by_field_name("condition") {
                if let Some(bound) = extract_for_upper_bound(&condition, source) {
                    return bound < alloc_count;
                }
            }
            return false; // in a for-loop but can't evaluate → safe default
        }
        // Don't walk past function boundaries
        if n.kind() == "function_definition" {
            break;
        }
        current = n.parent();
    }
    false
}

/// Extract the upper bound from a for-loop condition like `i < N` or `i <= N`.
fn extract_for_upper_bound(condition: &Node, source: &str) -> Option<usize> {
    if condition.kind() != "binary_expression" {
        return None;
    }
    let op = find_operator_text(condition, source);
    let right = condition.child_by_field_name("right")?;
    let macros = HashMap::new();
    match op {
        "<" => {
            let val = const_eval::try_evaluate_expr(&right, source, &macros)?;
            if val > 0 {
                Some(val as usize)
            } else {
                None
            }
        }
        "<=" => {
            let val = const_eval::try_evaluate_expr(&right, source, &macros)?;
            if val >= 0 {
                Some((val + 1) as usize)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Process an expression for initialization effects.
fn process_expression(
    node: &Node,
    source: &str,
    state: &mut InitStateMap,
    tracked_vars: &mut HashSet<String>,
    config: &InitAnalysisConfig,
) {
    match node.kind() {
        "assignment_expression" => {
            process_assignment_init(node, source, state, tracked_vars, config)
        }
        "update_expression" => {
            // i++ or ++i — the variable is being read AND written
            // If already tracked and initialized, no change needed
        }
        "call_expression" => {
            process_call_expression(node, source, state, tracked_vars, config);
        }
        "comma_expression" => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() != "," {
                        process_expression(&child, source, state, tracked_vars, config);
                    }
                }
            }
        }
        "cast_expression" => {
            // Unwrap (void)func(...) and similar casts to process the inner expression
            if let Some(value) = node.child_by_field_name("value") {
                process_expression(&value, source, state, tracked_vars, config);
            }
        }
        "parenthesized_expression" => {
            // Unwrap (expr) to process inner expression
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() != "(" && child.kind() != ")" {
                        process_expression(&child, source, state, tracked_vars, config);
                    }
                }
            }
        }
        "gnu_asm_expression" => {
            process_gnu_asm(node, source, state);
        }
        _ => {}
    }
}

/// `"assignment_expression"` case of [`process_expression`]: process the RHS
/// for side effects first, then resolve the LHS target and update its
/// tracked init-state.
fn process_assignment_init(
    node: &Node,
    source: &str,
    state: &mut InitStateMap,
    tracked_vars: &mut HashSet<String>,
    config: &InitAnalysisConfig,
) {
    // First, process the RHS for side effects (e.g., function calls
    // that initialize other variables via &output_param)
    if let Some(right) = node.child_by_field_name("right") {
        find_and_process_init_expressions(&right, source, state, tracked_vars, config);
    }

    // Then process the LHS assignment
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    let (var_name, has_subscript_in_chain) = extract_assignment_target(&left, source);
    if var_name.is_empty() {
        return;
    }

    // Pre-read: check if RHS is an uninitialized array identifier
    // (array-to-pointer decay: ptr = arr; where arr is uninit array).
    // Must read before the mutable borrow of var_name below.
    let array_decay = resolve_array_decay(&left, node, source, state);

    let Some(info) = state.get_mut(&var_name) else {
        return;
    };
    if left.kind() == "identifier" {
        apply_identifier_assignment_state(info, array_decay, node, source, config);
    } else {
        apply_lvalue_assignment_state(info, &left, has_subscript_in_chain, node, source);
    }
}

/// Resolve the assignment LHS to a tracked variable name plus whether the
/// access chain includes a subscript (which counts as a content write, even
/// through a field expression like `arr[0].field = val`).
fn extract_assignment_target(left: &Node, source: &str) -> (String, bool) {
    match left.kind() {
        "identifier" => (
            left.utf8_text(source.as_bytes()).unwrap_or("").to_string(),
            false,
        ),
        "pointer_expression" => (extract_deref_target(left, source), false),
        "subscript_expression" => (extract_subscript_base(left, source), true),
        "field_expression" => extract_nested_base_ex(left, source),
        _ => (String::new(), false),
    }
}

/// For a plain-identifier LHS whose RHS is itself an identifier, check
/// whether the RHS is an uninitialized non-char array (array-to-pointer
/// decay: `ptr = arr;`). Returns the RHS array's allocation count when so.
fn resolve_array_decay(
    left: &Node,
    node: &Node,
    source: &str,
    state: &InitStateMap,
) -> Option<Option<usize>> {
    if left.kind() != "identifier" {
        return None;
    }
    let right = node.child_by_field_name("right")?;
    if right.kind() != "identifier" {
        return None;
    }
    let rhs_name = right.utf8_text(source.as_bytes()).unwrap_or("");
    state.get(rhs_name).and_then(|rhs| {
        // Only apply to non-char arrays (int/double/struct).
        // Char arrays (CWE-665: strcat pattern) are flagged
        // at the assignment itself as the detection point.
        if rhs.is_array && rhs.state.is_unsafe() && !rhs.is_char_type {
            Some(rhs.allocation_count)
        } else {
            None
        }
    })
}

/// Apply an assignment `var = expr` to a plain-identifier target's tracked state.
fn apply_identifier_assignment_state(
    info: &mut VarInfo,
    array_decay: Option<Option<usize>>,
    node: &Node,
    source: &str,
    config: &InitAnalysisConfig,
) {
    if let Some(array_alloc) = array_decay {
        // Array-to-pointer decay: ptr = uninit_array
        // The pointer now points to uninitialized content.
        info.state = InitState::MallocUninitialized;
        info.allocation_count = array_alloc;
        return;
    }
    let Some(right) = node.child_by_field_name("right") else {
        info.state = InitState::Initialized;
        info.allocation_count = None;
        return;
    };
    info.state = classify_initializer(&right, source, config);
    info.allocation_count = if matches!(info.state, InitState::MallocUninitialized) {
        extract_allocation_count(&right, source)
    } else {
        None
    };
}

/// Apply an assignment through a deref/subscript/field LHS (`*p = expr`,
/// `arr[i] = expr`, `s.field = expr`) to the target's tracked state.
fn apply_lvalue_assignment_state(
    info: &mut VarInfo,
    left: &Node,
    has_subscript_in_chain: bool,
    node: &Node,
    source: &str,
) {
    match info.state {
        InitState::MallocUninitialized
            // Field writes (ptr->field = val) don't fully initialize
            // malloc'd memory — other fields/flexible array members may
            // remain uninitialized. Only subscript/deref writes upgrade
            // content state. But arr[0].field = val (subscript in chain)
            // should upgrade — it's writing content.
            if (left.kind() != "field_expression" || has_subscript_in_chain) =>
        {
            // Check for partial initialization: if inside a for-loop whose
            // bound < allocation_count, the loop only initializes a
            // fraction of elements.
            let stays_partial = info
                .allocation_count
                .is_some_and(|alloc_count| is_partial_init_write(alloc_count, node, source));
            if !stays_partial {
                info.state = InitState::MallocInitialized;
            }
            // else: keep MallocUninitialized — partial init
        }
        InitState::Uninitialized => {
            if left.kind() == "field_expression" && !has_subscript_in_chain {
                // Simple field write: s.field = val → initialized
                info.state = InitState::Initialized;
            }
            if left.kind() == "subscript_expression" {
                info.state = InitState::Initialized;
            }
        }
        _ => {}
    }
}

/// Recursively search a node tree for init-relevant expressions (assignments,
/// calls, comma expressions) that may be nested inside conditions, casts, etc.
fn find_and_process_init_expressions(
    node: &Node,
    source: &str,
    state: &mut InitStateMap,
    tracked_vars: &mut HashSet<String>,
    config: &InitAnalysisConfig,
) {
    match node.kind() {
        "assignment_expression" | "call_expression" | "comma_expression" | "update_expression" => {
            process_expression(node, source, state, tracked_vars, config);
        }
        "gnu_asm_expression" => {
            process_gnu_asm(node, source, state);
        }
        _ => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    find_and_process_init_expressions(&child, source, state, tracked_vars, config);
                }
            }
        }
    }
}

/// Handle `__asm("..." : "=r"(var) ...)` which tree-sitter-c misparsed as a
/// `call_expression`. The output operands become nested `call_expression` nodes
/// with a `string_literal` as the function. Find any such operand whose
/// constraint contains `=` and mark its identifier argument as Initialized.
fn process_misparsed_asm_call(node: &Node, source: &str, state: &mut InitStateMap) {
    let Some(args) = node.child_by_field_name("arguments") else {
        return;
    };
    collect_asm_output_inits(&args, source, state);
}

/// Recursively walk an argument-list (or ERROR node inside it) looking for
/// `"=r"(var)` / `"=m"(var)` patterns — misparsed asm output operands.
/// When found, mark the identifier argument as Initialized.
fn collect_asm_output_inits(node: &Node, source: &str, state: &mut InitStateMap) {
    for i in 0..node.child_count() {
        let Some(child) = node.child(i) else { continue };
        match child.kind() {
            "call_expression" => {
                let Some(func) = child.child_by_field_name("function") else {
                    continue;
                };
                if func.kind() != "string_literal" {
                    continue;
                }
                let constraint = func.utf8_text(source.as_bytes()).unwrap_or("");
                if !constraint.contains('=') {
                    continue; // input operand
                }
                let Some(inner_args) = child.child_by_field_name("arguments") else {
                    continue;
                };
                for j in 0..inner_args.child_count() {
                    let Some(ident) = inner_args.child(j) else {
                        continue;
                    };
                    if ident.kind() == "identifier" {
                        let name = ident.utf8_text(source.as_bytes()).unwrap_or("");
                        if !name.is_empty() {
                            if let Some(info) = state.get_mut(name) {
                                info.state = InitState::Initialized;
                                info.allocation_count = None;
                            }
                        }
                    }
                }
            }
            "ERROR" => {
                // Output operand may be nested inside an ERROR node
                collect_asm_output_inits(&child, source, state);
            }
            _ => {}
        }
    }
}

/// Mark variables written by GNU inline asm output operands as initialized.
///
/// Output operands appear as `gnu_asm_output_operand` nodes under the
/// `output_operands` field of the `gnu_asm_expression`. Each operand has a
/// `value` field that is the destination identifier (e.g., `result` in
/// `"=r"(result)`). These are written by the asm, not read, so they should
/// be treated as freshly initialized after the statement.
fn process_gnu_asm(node: &Node, source: &str, state: &mut InitStateMap) {
    let Some(output_list) = node.child_by_field_name("output_operands") else {
        return;
    };
    for i in 0..output_list.child_count() {
        let Some(child) = output_list.child(i) else {
            continue;
        };
        if child.kind() != "gnu_asm_output_operand" {
            continue;
        }
        if let Some(val) = child.child_by_field_name("value") {
            let name = val.utf8_text(source.as_bytes()).unwrap_or("");
            if !name.is_empty() {
                if let Some(info) = state.get_mut(name) {
                    info.state = InitState::Initialized;
                    info.allocation_count = None;
                }
            }
        }
    }
}

/// Process a call expression for initialization effects.
fn process_call_expression(
    node: &Node,
    source: &str,
    state: &mut InitStateMap,
    _tracked_vars: &mut HashSet<String>,
    config: &InitAnalysisConfig,
) {
    let Some(func) = node.child_by_field_name("function") else {
        return;
    };
    let func_name = func.utf8_text(source.as_bytes()).unwrap_or("").to_string();
    let func_name_lower = func_name.to_lowercase();

    if try_process_misparsed_asm_output_operand(&func, &func_name, node, source, state) {
        return;
    }

    // `__asm(...)` / `__ASM(...)` are not recognised as gnu_asm_expression by
    // tree-sitter-c (only `asm` and `__asm__` are). They parse as call_expression,
    // and the output operands `"=r"(var)` become nested call_expressions whose
    // function is a string_literal. Walk the argument list and mark any identifier
    // that is the sole argument of a string_literal-function call with `=` in it.
    if func_name_lower.starts_with("__asm") || func_name_lower == "asm" {
        process_misparsed_asm_call(node, source, state);
        return;
    }

    if try_process_va_start(&func_name, node, source, state) {
        return;
    }
    if try_process_registered_macro(&func_name, node, source, state) {
        return;
    }
    if try_process_macro_output_params(&func_name, node, source, state, config) {
        return;
    }
    if try_process_known_initializing_function(&func_name, node, source, state) {
        return;
    }

    // Cross-file summary says this function writes through specific params
    // (task 195/319 follow-on). Apply the marking, but don't treat it as a
    // complete answer: `modifies_params` is a flow-insensitive text scan that
    // can under-count (e.g. writes via a nested helper call), so still fall
    // through to `process_unknown_function_call`'s broader default below —
    // marking an already-Initialized var again is a harmless no-op, and
    // skipping that fallback here would silently drop the coverage it gives
    // to other params on the same call that the summary missed.
    try_process_cross_file_output_params(&func_name, node, source, state, config);

    // Non-initializing functions: skip (they read, not write)
    if is_non_initializing_function(&func_name) {
        return;
    }

    process_unknown_function_call(&func_name, node, source, state, config);
}

/// Misparsed asm output operand: `"=r"(var)` or `"+r"(var)`. tree-sitter-c
/// sees the constraint string as the callee function. Mark the identifier
/// argument as initialized — it is written by the asm.
fn try_process_misparsed_asm_output_operand(
    func: &Node,
    func_name: &str,
    node: &Node,
    source: &str,
    state: &mut InitStateMap,
) -> bool {
    if func.kind() != "string_literal" || !func_name.contains('=') {
        return false;
    }
    if let Some(args) = node.child_by_field_name("arguments") {
        for i in 0..args.child_count() {
            let Some(arg) = args.child(i) else { continue };
            if arg.kind() != "identifier" {
                continue;
            }
            let name = arg.utf8_text(source.as_bytes()).unwrap_or("");
            if name.is_empty() {
                continue;
            }
            if let Some(info) = state.get_mut(name) {
                info.state = InitState::Initialized;
                info.allocation_count = None;
            }
        }
    }
    true
}

/// `va_start`/`va_copy` initializes its first argument (the va_list variable).
fn try_process_va_start(
    func_name: &str,
    node: &Node,
    source: &str,
    state: &mut InitStateMap,
) -> bool {
    if func_name != "va_start" && func_name != "va_copy" {
        return false;
    }
    if let Some(args) = node.child_by_field_name("arguments") {
        for i in 0..args.child_count() {
            let Some(arg) = args.child(i) else { continue };
            if arg.kind() == "identifier" {
                let var_name = arg.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                if let Some(info) = state.get_mut(&var_name) {
                    info.state = InitState::Initialized;
                }
                break; // Only first arg
            }
        }
    }
    true
}

/// Iterator/find/output macros (utlist/uthash/BSD-queue): the macro writes
/// its iterator/temp/out positional args. Mark each as initialized. See
/// `macro_semantics` (Phase 1 of docs/design/macro-expansion.md) — this
/// replaces the old first-arg-only FOR_EACH_MACROS heuristic, which was wrong
/// for utlist/uthash where the head is the input at arg 0.
fn try_process_registered_macro(
    func_name: &str,
    node: &Node,
    source: &str,
    state: &mut InitStateMap,
) -> bool {
    if !crate::analyze::macro_semantics::is_registered(func_name) {
        return false;
    }
    for (var_name, _role) in crate::analyze::macro_semantics::output_var_args(node, source) {
        if let Some(info) = state.get_mut(&var_name) {
            info.state = InitState::Initialized;
        }
    }
    true
}

/// Function-like macros whose body assigns one of their parameters (e.g.
/// curl's `CF_DATA_SAVE(save, cf, data)` → `(save) = …`). The expander
/// (`macro_expand::macro_output_param_indices`) precomputes which positional
/// args are *written*; mark each bare-identifier output arg as initialized so
/// downstream reads of it are not "used uninitialized" FPs. Phase 2c-ii of
/// docs/design/macro-expansion.md.
fn try_process_macro_output_params(
    func_name: &str,
    node: &Node,
    source: &str,
    state: &mut InitStateMap,
    config: &InitAnalysisConfig,
) -> bool {
    let Some(out_indices) = config.macro_output_params.get(func_name) else {
        return false;
    };
    let args = crate::analyze::macro_semantics::positional_args(node);
    for &idx in out_indices {
        if let Some(arg) = args.get(idx) {
            if arg.kind() == "identifier" {
                let name = arg.utf8_text(source.as_bytes()).unwrap_or("");
                if let Some(info) = state.get_mut(name) {
                    info.state = InitState::Initialized;
                    info.allocation_count = None;
                }
            }
        }
    }
    true
}

/// Cross-file (in-repo) functions known from prescan `FunctionSummary::modifies_params`
/// to write through a pointer param: mark `&var`/bare-pointer output args as initialized.
/// Mirrors `try_process_known_initializing_function` but sourced from actual function
/// bodies rather than a curated stdlib name table.
fn try_process_cross_file_output_params(
    func_name: &str,
    node: &Node,
    source: &str,
    state: &mut InitStateMap,
    config: &InitAnalysisConfig,
) -> bool {
    let Some(output_indices) = config.cross_file_output_params.get(func_name) else {
        return false;
    };
    let Some(args) = node.child_by_field_name("arguments") else {
        return false;
    };
    let mut arg_idx = 0;
    let mut matched = false;
    for i in 0..args.child_count() {
        let Some(arg) = args.child(i) else { continue };
        if matches!(arg.kind(), "," | "(" | ")") {
            continue;
        }
        if output_indices.contains(&arg_idx) {
            let var_name = extract_var_from_arg(&arg, source);
            if !var_name.is_empty() {
                if let Some(info) = state.get_mut(&var_name) {
                    info.state = InitState::Initialized;
                    info.allocation_count = None;
                    matched = true;
                }
            }
        }
        arg_idx += 1;
    }
    matched
}

/// Known initializing functions (exact or suffix match): mark output args as initialized.
fn try_process_known_initializing_function(
    func_name: &str,
    node: &Node,
    source: &str,
    state: &mut InitStateMap,
) -> bool {
    let Some(base_name) = match_initializing_function(func_name) else {
        return false;
    };
    let output_indices = get_output_arg_indices(base_name);
    if let Some(args) = node.child_by_field_name("arguments") {
        let mut arg_idx = 0;
        for i in 0..args.child_count() {
            let Some(arg) = args.child(i) else { continue };
            if matches!(arg.kind(), "," | "(" | ")") {
                continue;
            }
            if output_indices.contains(&arg_idx) {
                let var_name = extract_var_from_arg(&arg, source);
                if !var_name.is_empty() {
                    if let Some(info) = state.get_mut(&var_name) {
                        // memset on a malloc'd pointer → MallocInitialized
                        if base_name == "memset"
                            && matches!(
                                info.state,
                                InitState::MallocUninitialized | InitState::MallocInitialized
                            )
                        {
                            info.state = InitState::MallocInitialized;
                        } else {
                            info.state = InitState::Initialized;
                        }
                    }
                }
            }
            arg_idx += 1;
        }
    }
    true
}

/// Unknown function: assume `&var` initializes (conservative — most
/// functions that take pointer params write to them), UNLESS the specific
/// parameter is known to be only conditionally initialized or read-only
/// dereferenced. Also handles arrays passed by name.
fn process_unknown_function_call(
    func_name: &str,
    node: &Node,
    source: &str,
    state: &mut InitStateMap,
    config: &InitAnalysisConfig,
) {
    let cond_param_indices = config.conditionally_init_fns.get(func_name);
    let read_only_indices = config.read_only_deref_fns.get(func_name);

    let Some(args) = node.child_by_field_name("arguments") else {
        return;
    };
    let mut arg_idx: usize = 0;
    for i in 0..args.child_count() {
        let Some(arg) = args.child(i) else { continue };
        if matches!(arg.kind(), "," | "(" | ")") {
            continue;
        }
        let skip_this_arg = cond_param_indices.is_some_and(|indices| indices.contains(&arg_idx))
            || read_only_indices.is_some_and(|indices| indices.contains(&arg_idx));
        // &var pattern — assume function writes to it (unless this param is conditionally-init)
        if !skip_this_arg && arg.kind() == "pointer_expression" {
            let arg_text = arg.utf8_text(source.as_bytes()).unwrap_or("");
            if arg_text.starts_with('&') {
                let var_name = extract_var_from_arg(&arg, source);
                if !var_name.is_empty() {
                    if let Some(info) = state.get_mut(&var_name) {
                        info.state = InitState::Initialized;
                    }
                }
            }
        }
        // Array passed by name — assume function writes to it
        if !skip_this_arg && arg.kind() == "identifier" {
            let var_name = arg.utf8_text(source.as_bytes()).unwrap_or("").to_string();
            if let Some(info) = state.get(&var_name) {
                if info.is_array {
                    let info = state.get_mut(&var_name).unwrap();
                    info.state = InitState::Initialized;
                }
            }
        }
        arg_idx += 1;
    }
}

// ---------------------------------------------------------------------------
// Worklist algorithm
// ---------------------------------------------------------------------------

/// Run init-state forward dataflow analysis on a function.
#[allow(dead_code)]
pub fn analyze_init_states(
    cfg: &FunctionCfg,
    func_node: &Node,
    source: &str,
) -> InitAnalysisResult {
    analyze_init_states_with_statics(
        cfg,
        func_node,
        source,
        &InitStateMap::new(),
        &InitAnalysisConfig::default(),
    )
}

/// Like `analyze_init_states` but seeds with file-scope static variable states.
pub fn analyze_init_states_with_statics(
    cfg: &FunctionCfg,
    func_node: &Node,
    source: &str,
    static_vars: &InitStateMap,
    config: &InitAnalysisConfig,
) -> InitAnalysisResult {
    let body = match func_node.child_by_field_name("body") {
        Some(b) => b,
        None => {
            return InitAnalysisResult {
                block_entry_states: HashMap::new(),
                block_exit_states: HashMap::new(),
                tracked_vars: HashSet::new(),
            };
        }
    };

    let mut tracked_vars = HashSet::new();

    // Initialize entry state: parameters → Initialized, statics → from pre-scan
    let mut initial_state = InitStateMap::new();

    // Seed with static variable states
    for (name, info) in static_vars {
        initial_state.insert(name.clone(), info.clone());
        tracked_vars.insert(name.clone());
    }

    // Function parameters are always initialized (caller provides them)
    collect_param_init_state(func_node, source, &mut initial_state, &mut tracked_vars);

    let mut entry_states: HashMap<BlockId, InitStateMap> = HashMap::new();
    let mut exit_states: HashMap<BlockId, InitStateMap> = HashMap::new();

    // Initialize all blocks
    for block in &cfg.blocks {
        entry_states.insert(block.id, InitStateMap::new());
        exit_states.insert(block.id, InitStateMap::new());
    }

    // Entry block gets initial state
    entry_states.insert(cfg.entry, initial_state.clone());
    let entry_exit = apply_transfer(
        &cfg.blocks[cfg.entry],
        &initial_state,
        &body,
        source,
        &mut tracked_vars,
        config,
    );
    exit_states.insert(cfg.entry, entry_exit);

    // Worklist
    // Track which blocks have been visited (have computed exit states)
    let mut visited: HashSet<BlockId> = HashSet::new();
    visited.insert(cfg.entry);

    let mut worklist: VecDeque<BlockId> = VecDeque::new();
    for (succ, _) in cfg.successors(cfg.entry) {
        worklist.push_back(succ);
    }

    let mut iterations = 0;
    let max_iterations = 500 * cfg.blocks.len().max(1);

    while let Some(block_id) = worklist.pop_front() {
        iterations += 1;
        if iterations > max_iterations {
            break;
        }

        // Join predecessor exit states
        let preds = cfg.predecessors(block_id);
        let mut new_entry = InitStateMap::new();
        let mut first = true;

        for (pred_id, edge_kind) in &preds {
            if !visited.contains(pred_id) {
                continue;
            }

            // Dead-branch elimination: if a predecessor block has a condition
            // that evaluates to a known constant, skip the impossible edge.
            if matches!(edge_kind, CfgEdge::TrueBranch | CfgEdge::FalseBranch) {
                let pred_block = &cfg.blocks[*pred_id];
                if let Some(cond_val) = try_evaluate_block_condition(
                    pred_block,
                    &body,
                    source,
                    &config.file_scope_constants,
                ) {
                    let on_true_edge = matches!(edge_kind, CfgEdge::TrueBranch);
                    if cond_val != on_true_edge {
                        continue; // dead edge — skip
                    }
                }
            }

            let pred_exit = exit_states.get(pred_id).cloned().unwrap_or_default();

            if first {
                new_entry = pred_exit;
                first = false;
            } else if matches!(edge_kind, CfgEdge::Goto) {
                // Goto edge: variables in new_entry but not pred_exit
                // were declared between goto and label (skipped).
                new_entry = join_with_goto(&new_entry, &pred_exit);
            } else {
                new_entry = join_states(&new_entry, &pred_exit);
            }
        }

        if first {
            // No predecessors (unreachable block) — skip
            continue;
        }

        // Compute exit state
        let block = &cfg.blocks[block_id];
        let new_exit = apply_transfer(block, &new_entry, &body, source, &mut tracked_vars, config);

        // Check convergence
        let old_exit = exit_states.get(&block_id);
        let changed = match old_exit {
            None => true,
            Some(old) => *old != new_exit,
        };

        visited.insert(block_id);

        if changed {
            entry_states.insert(block_id, new_entry);
            exit_states.insert(block_id, new_exit);

            for (succ, _) in cfg.successors(block_id) {
                if !worklist.contains(&succ) {
                    worklist.push_back(succ);
                }
            }
        } else {
            entry_states.insert(block_id, new_entry);
        }
    }

    InitAnalysisResult {
        block_entry_states: entry_states,
        block_exit_states: exit_states,
        tracked_vars,
    }
}

// ---------------------------------------------------------------------------
// Point queries
// ---------------------------------------------------------------------------

/// Check if a variable is uninitialized at a given byte offset.
/// Returns Some(info) if unsafe, None if safe or unknown.
#[allow(dead_code)]
pub fn get_var_info_at(
    result: &InitAnalysisResult,
    cfg: &FunctionCfg,
    body: &Node,
    source: &str,
    var_name: &str,
    byte_offset: usize,
) -> Option<VarInfo> {
    get_var_info_at_with_config(
        result,
        cfg,
        body,
        source,
        var_name,
        byte_offset,
        &InitAnalysisConfig::default(),
    )
}

/// Like `get_var_info_at` but with explicit analysis config.
pub fn get_var_info_at_with_config(
    result: &InitAnalysisResult,
    cfg: &FunctionCfg,
    body: &Node,
    source: &str,
    var_name: &str,
    byte_offset: usize,
    config: &InitAnalysisConfig,
) -> Option<VarInfo> {
    let block = find_block_containing(cfg, byte_offset)?;

    let entry = result.block_entry_states.get(&block.id)?;

    let mut state = entry.clone();
    let mut tracked = result.tracked_vars.clone();

    for &(start, end) in &block.statements {
        if start >= byte_offset {
            break;
        }
        if end <= byte_offset {
            if let Some(stmt_node) = find_node_at_range(body, start, end) {
                process_statement(&stmt_node, source, &mut state, &mut tracked, config);
            }
        } else {
            // Statement contains byte_offset. For switch statements, replay
            // same-case sub-statements that precede the target. For
            // if/while/for, replay earlier clauses of a still-in-progress
            // short-circuited condition (see task 322).
            if let Some(stmt_node) = find_node_at_range(body, start, end) {
                if stmt_node.kind() == "switch_statement" {
                    replay_within_switch_case(
                        &stmt_node,
                        source,
                        &mut state,
                        &mut tracked,
                        config,
                        byte_offset,
                    );
                } else if matches!(
                    stmt_node.kind(),
                    "binary_expression" | "parenthesized_expression"
                ) {
                    // `add_statement` records if/while/for conditions by their
                    // own byte range (not the enclosing statement's), so the
                    // node found here IS the condition expression itself.
                    replay_short_circuit_operands(
                        &stmt_node,
                        source,
                        &mut state,
                        &mut tracked,
                        config,
                        byte_offset,
                    );
                }
            }
        }
    }

    state.get(var_name).cloned()
}

/// Find the basic block whose byte range contains the given offset.
fn find_block_containing(cfg: &FunctionCfg, byte_offset: usize) -> Option<&BasicBlock> {
    // First try statement-level containment (more precise)
    for block in &cfg.blocks {
        for &(start, end) in &block.statements {
            if byte_offset >= start && byte_offset < end {
                return Some(block);
            }
        }
    }
    // Fallback to block byte range
    cfg.blocks.iter().find(|block| {
        block.byte_range.0 > 0
            && byte_offset >= block.byte_range.0
            && byte_offset < block.byte_range.1
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Collect function parameter initialization states.
fn collect_param_init_state(
    func_node: &Node,
    source: &str,
    state: &mut InitStateMap,
    tracked_vars: &mut HashSet<String>,
) {
    let declarator = match func_node.child_by_field_name("declarator") {
        Some(d) => d,
        None => return,
    };

    // Find the function_declarator (may be nested inside pointer_declarator)
    let func_decl = find_function_declarator(&declarator);
    let func_decl = match func_decl {
        Some(d) => d,
        None => return,
    };

    // Find parameter_list
    for i in 0..func_decl.child_count() {
        if let Some(child) = func_decl.child(i) {
            if child.kind() == "parameter_list" {
                for j in 0..child.child_count() {
                    if let Some(param) = child.child(j) {
                        if param.kind() == "parameter_declaration" {
                            let param_name = get_declarator_name(&param, source);
                            if !param_name.is_empty() {
                                let type_text = extract_type_text(&param, source);
                                let is_unsigned_char = type_text.contains("unsigned char")
                                    || type_text.contains("uint8_t");
                                let is_array = param_has_array_declarator(&param);
                                let mut info = VarInfo::new(InitState::Initialized);
                                info.is_unsigned_char = is_unsigned_char;
                                info.is_array = is_array;
                                state.insert(param_name.clone(), info);
                                tracked_vars.insert(param_name);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn find_function_declarator<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    if node.kind() == "function_declarator" {
        return Some(*node);
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if let Some(found) = find_function_declarator(&child) {
                return Some(found);
            }
        }
    }
    None
}

/// Extract the type text from a declaration node.
fn extract_type_text(node: &Node, source: &str) -> String {
    let mut parts = Vec::new();
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "primitive_type"
                | "sized_type_specifier"
                | "type_identifier"
                | "storage_class_specifier"
                | "type_qualifier" => {
                    if let Ok(t) = child.utf8_text(source.as_bytes()) {
                        parts.push(t.to_string());
                    }
                }
                _ => {}
            }
        }
    }
    parts.join(" ")
}

/// Get the variable name from a declarator node.
fn get_declarator_name(node: &Node, source: &str) -> String {
    // Direct identifier
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "identifier" {
                return child.utf8_text(source.as_bytes()).unwrap_or("").to_string();
            }
        }
    }
    // Recurse into nested declarators
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "init_declarator"
                | "pointer_declarator"
                | "array_declarator"
                | "function_declarator" => {
                    let name = get_declarator_name(&child, source);
                    if !name.is_empty() {
                        return name;
                    }
                }
                _ => {}
            }
        }
    }
    String::new()
}

fn is_array_declarator(node: &Node) -> bool {
    if node.kind() == "array_declarator" {
        return true;
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if is_array_declarator(&child) {
                return true;
            }
        }
    }
    false
}

fn param_has_array_declarator(node: &Node) -> bool {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "array_declarator" {
                return true;
            }
            if param_has_array_declarator(&child) {
                return true;
            }
        }
    }
    false
}

fn is_type_keyword(s: &str) -> bool {
    matches!(
        s,
        "int"
            | "char"
            | "short"
            | "long"
            | "float"
            | "double"
            | "void"
            | "unsigned"
            | "signed"
            | "const"
            | "volatile"
            | "static"
            | "extern"
            | "register"
            | "auto"
            | "struct"
            | "union"
            | "enum"
            | "typedef"
    )
}

fn get_text(_parent: &Node, child: &Node, source: &str) -> String {
    child.utf8_text(source.as_bytes()).unwrap_or("").to_string()
}

/// Extract variable name from function argument (handles &var, var).
fn extract_var_from_arg(arg: &Node, source: &str) -> String {
    if arg.kind() == "pointer_expression" {
        let text = arg.utf8_text(source.as_bytes()).unwrap_or("");
        if text.starts_with('&') {
            if let Some(inner) = arg.child_by_field_name("argument") {
                if inner.kind() == "identifier" {
                    return inner.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                }
            }
        }
    } else if arg.kind() == "identifier" {
        return arg.utf8_text(source.as_bytes()).unwrap_or("").to_string();
    }
    String::new()
}

/// Extract the target variable from a dereference: *ptr → "ptr"
fn extract_deref_target(node: &Node, source: &str) -> String {
    if let Some(arg) = node.child_by_field_name("argument") {
        if arg.kind() == "identifier" {
            return arg.utf8_text(source.as_bytes()).unwrap_or("").to_string();
        }
    }
    String::new()
}

/// Extract the base variable from a subscript: arr[i] → "arr"
fn extract_subscript_base(node: &Node, source: &str) -> String {
    extract_nested_base(node, source)
}

/// Recursively extract the base identifier from nested field/subscript expressions.
/// Handles chains like `arr[0].field`, `s.arr[0]`, `ptr->arr[i].field`, etc.
/// Returns (base_name, has_subscript_in_chain).
fn extract_nested_base_ex(node: &Node, source: &str) -> (String, bool) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "identifier" => {
                    let name = child.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                    return (name, false);
                }
                "subscript_expression" => {
                    let (name, _) = extract_nested_base_ex(&child, source);
                    if !name.is_empty() {
                        return (name, true);
                    }
                }
                "field_expression" | "parenthesized_expression" => {
                    let result = extract_nested_base_ex(&child, source);
                    if !result.0.is_empty() {
                        return result;
                    }
                }
                _ => {}
            }
        }
    }
    (String::new(), false)
}

fn extract_nested_base(node: &Node, source: &str) -> String {
    extract_nested_base_ex(node, source).0
}

/// Collect file-scope static variable init states.
pub fn collect_file_scope_statics(root: &Node, source: &str) -> InitStateMap {
    let mut state = InitStateMap::new();
    collect_file_scope_statics_recursive(root, source, &mut state);
    state
}

fn collect_file_scope_statics_recursive(node: &Node, source: &str, state: &mut InitStateMap) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "declaration" => {
                    let type_text = extract_type_text(&child, source);
                    let is_static =
                        type_text.contains("static") || type_text.contains("_Thread_local");
                    if is_static {
                        let mut tracked = HashSet::new();
                        process_declaration(
                            &child,
                            source,
                            state,
                            &mut tracked,
                            &InitAnalysisConfig::default(),
                        );
                    }
                }
                "preproc_ifdef" | "preproc_if" | "preproc_else" | "preproc_elif" => {
                    collect_file_scope_statics_recursive(&child, source, state);
                }
                _ => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// File-scope constant collection (for dead-branch elimination)
// ---------------------------------------------------------------------------

/// Collect file-scope constants: `static [const] TYPE NAME = VALUE;` and
/// `const TYPE NAME = VALUE;` where VALUE is a compile-time constant.
/// Used by init-state dead-branch elimination to resolve opaque predicates.
pub fn collect_file_scope_constants(root: &Node, source: &str) -> HashMap<String, i64> {
    let mut constants = HashMap::new();
    collect_constants_recursive(root, source, &mut constants);
    constants
}

fn collect_constants_recursive(node: &Node, source: &str, constants: &mut HashMap<String, i64>) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "declaration" => {
                    let type_text = extract_type_text(&child, source);
                    // Accept: static const, static, or const at file scope
                    let is_static_or_const =
                        type_text.contains("static") || type_text.contains("const");
                    if !is_static_or_const {
                        continue;
                    }
                    // Walk declarators looking for init_declarator with a value
                    for j in 0..child.child_count() {
                        if let Some(decl) = child.child(j) {
                            if decl.kind() == "init_declarator" {
                                let name = get_declarator_name(&decl, source);
                                if name.is_empty() {
                                    continue;
                                }
                                if let Some(value) = decl.child_by_field_name("value") {
                                    let empty_macros: HashMap<String, i64> = HashMap::new();
                                    if let Some(val) =
                                        const_eval::try_evaluate_expr(&value, source, &empty_macros)
                                    {
                                        constants.insert(name, val);
                                    }
                                }
                            }
                        }
                    }
                }
                "preproc_ifdef" | "preproc_if" | "preproc_else" | "preproc_elif" => {
                    collect_constants_recursive(&child, source, constants);
                }
                _ => {}
            }
        }
    }
}

/// Collect zero-argument functions with a single `return LITERAL;` body.
/// These are constant-valued functions that can be used in dead-branch elimination
/// (e.g., `staticReturnsTrue()`, `globalReturnsFalse()`).
pub fn collect_constant_functions(root: &Node, source: &str) -> HashMap<String, i64> {
    let mut result = HashMap::new();
    collect_constant_functions_in(root, source, &mut result);
    result
}

fn collect_constant_functions_in(node: &Node, source: &str, result: &mut HashMap<String, i64>) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "function_definition" => {
                    if let Some((name, val)) = extract_constant_function(&child, source) {
                        result.insert(name, val);
                    }
                }
                "preproc_ifdef" | "preproc_if" | "preproc_else" | "preproc_elif"
                | "preproc_ifndef" => {
                    collect_constant_functions_in(&child, source, result);
                }
                _ => {}
            }
        }
    }
}

/// If `func_node` is a zero-argument function whose body is exactly `return LITERAL;`,
/// return `(name, value)`. Otherwise return `None`.
fn extract_constant_function(func_node: &Node, source: &str) -> Option<(String, i64)> {
    let declarator = func_node.child_by_field_name("declarator")?;
    let func_decl = find_function_declarator(&declarator)?;

    // Params must be empty or just "void"
    let params = func_decl.child_by_field_name("parameters")?;
    let named_count = params.named_child_count();
    if named_count > 1 {
        return None;
    }
    if named_count == 1 {
        let p = params.named_child(0)?;
        let text = p.utf8_text(source.as_bytes()).ok()?;
        if text != "void" {
            return None;
        }
    }

    // Extract function name
    let name = get_declarator_name(&func_decl, source);
    if name.is_empty() {
        return None;
    }

    // Body must contain exactly one return_statement with a constant value
    let body = func_node.child_by_field_name("body")?;
    let mut return_val: Option<i64> = None;
    let mut non_return_stmts = 0usize;
    for i in 0..body.child_count() {
        if let Some(stmt) = body.child(i) {
            match stmt.kind() {
                "{" | "}" => {}
                "return_statement" => {
                    // Find the expression child (skip 'return' keyword and ';')
                    for j in 0..stmt.child_count() {
                        if let Some(child) = stmt.child(j) {
                            if child.kind() != "return" && child.kind() != ";" {
                                let empty: HashMap<String, i64> = HashMap::new();
                                return_val = const_eval::try_evaluate_expr(&child, source, &empty);
                            }
                        }
                    }
                }
                _ => {
                    non_return_stmts += 1;
                }
            }
        }
    }

    if non_return_stmts > 0 {
        return None;
    }

    return_val.map(|v| (name, v))
}

/// Replay init-state transfers for sub-statements within the same switch case
/// as `byte_offset`, processing only those that end before `byte_offset`.
fn replay_within_switch_case(
    switch_node: &Node,
    source: &str,
    state: &mut InitStateMap,
    tracked: &mut HashSet<String>,
    config: &InitAnalysisConfig,
    byte_offset: usize,
) {
    // Find the switch body (compound_statement)
    for i in 0..switch_node.child_count() {
        if let Some(child) = switch_node.child(i) {
            if child.kind() == "compound_statement" {
                // Find the case_statement whose range contains byte_offset
                for j in 0..child.child_count() {
                    if let Some(case_node) = child.child(j) {
                        if case_node.kind() == "case_statement"
                            && case_node.start_byte() < byte_offset
                            && case_node.end_byte() > byte_offset
                        {
                            // Replay sub-statements of this case that end before byte_offset
                            for k in 0..case_node.child_count() {
                                if let Some(stmt) = case_node.child(k) {
                                    if stmt.end_byte() <= byte_offset {
                                        process_statement(&stmt, source, state, tracked, config);
                                    } else if stmt.start_byte() >= byte_offset {
                                        break;
                                    }
                                }
                            }
                            return;
                        }
                    }
                }
                break;
            }
        }
    }
}

/// Recursively unwrap a (possibly parenthesized) short-circuit `&&`/`||`
/// chain and process every operand that lexically precedes `byte_offset`.
fn replay_short_circuit_operands(
    node: &Node,
    source: &str,
    state: &mut InitStateMap,
    tracked: &mut HashSet<String>,
    config: &InitAnalysisConfig,
    byte_offset: usize,
) {
    let mut n = *node;
    while n.kind() == "parenthesized_expression" {
        if let Some(inner) = n.child(1) {
            n = inner;
        } else {
            return;
        }
    }

    if n.kind() != "binary_expression" {
        return;
    }
    let op = n
        .child_by_field_name("operator")
        .map(|o| o.utf8_text(source.as_bytes()).unwrap_or(""))
        .unwrap_or("");
    if op != "&&" && op != "||" {
        return;
    }
    let (Some(left), Some(right)) = (
        n.child_by_field_name("left"),
        n.child_by_field_name("right"),
    ) else {
        return;
    };

    if byte_offset < right.start_byte() {
        // Target is within (or before) the left operand: recurse so any
        // earlier clauses nested further left are replayed too.
        replay_short_circuit_operands(&left, source, state, tracked, config, byte_offset);
    } else {
        // Target is within the right operand: the entire left operand has
        // already fully evaluated, so apply all of its effects, then
        // recurse into the right in case it is itself a nested chain.
        find_and_process_init_expressions(&left, source, state, tracked, config);
        replay_short_circuit_operands(&right, source, state, tracked, config, byte_offset);
    }
}

/// Try to evaluate a condition in a CFG block as a compile-time constant.
/// Returns `Some(true)` if always true, `Some(false)` if always false, `None` if unknown.
pub fn try_evaluate_block_condition(
    block: &BasicBlock,
    body: &Node,
    source: &str,
    constants: &HashMap<String, i64>,
) -> Option<bool> {
    let (cond_start, cond_end) = block.condition_range?;
    let cond_node = body.descendant_for_byte_range(cond_start, cond_end)?;
    // Use file-scope constants as macro constants for evaluation
    let val = const_eval::try_evaluate_expr(&cond_node, source, constants)?;
    Some(val != 0) // C truthiness: 0 is false, anything else is true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::cfg::build_function_cfg;

    fn analyze_code(code: &str) -> (FunctionCfg, InitAnalysisResult, String) {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let root = tree.root_node();

        for i in 0..root.child_count() {
            if let Some(child) = root.child(i) {
                if child.kind() == "function_definition" {
                    let cfg = build_function_cfg(&child, code).unwrap();
                    let result = analyze_init_states(&cfg, &child, code);
                    return (cfg, result, code.to_string());
                }
            }
        }
        panic!("No function definition found");
    }

    #[test]
    fn test_uninitialized_simple() {
        let code = "void foo() { int x; x = x + 1; }";
        let (cfg, result, source) = analyze_code(code);

        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(&source, None).unwrap();
        let root = tree.root_node();
        let func = root.child(0).unwrap();
        let body = func.child_by_field_name("body").unwrap();

        // x should be uninitialized when first used
        let info = get_var_info_at(
            &result,
            &cfg,
            &body,
            &source,
            "x",
            code.find("x + 1").unwrap(),
        );
        assert!(info.is_some());
        assert!(info.unwrap().state.is_unsafe());
    }

    #[test]
    fn test_initialized_simple() {
        let code = "void foo() { int x = 5; int y = x + 1; }";
        let (cfg, result, source) = analyze_code(code);

        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(&source, None).unwrap();
        let func = tree.root_node().child(0).unwrap();
        let body = func.child_by_field_name("body").unwrap();

        let info = get_var_info_at(
            &result,
            &cfg,
            &body,
            &source,
            "x",
            source.find("x + 1").unwrap(),
        );
        assert!(info.is_some());
        assert!(!info.unwrap().state.is_unsafe());
    }

    #[test]
    fn test_cross_file_output_param_marks_initialized() {
        // task 195/319 follow-on: a cross-file (non-macro, non-stdlib) function
        // known from FunctionSummary::modifies_params to write through param
        // index 2 (mirrors hostap's `erp_parse_tlvs(pos, end, &tlvs, flag)`)
        // must mark the address-of'd variable as Initialized.
        let code = r#"
        void foo(void) {
            struct tlvs parse;
            if (erp_parse_tlvs(pos, end, &parse, 1) < 0)
                return;
            use(parse.keyname);
        }
        "#;
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let func = tree.root_node().child(0).unwrap();
        let body = func.child_by_field_name("body").unwrap();
        let cfg = build_function_cfg(&func, code).unwrap();

        let mut cross_file_output_params = HashMap::new();
        cross_file_output_params.insert("erp_parse_tlvs".to_string(), HashSet::from([2usize]));
        let config = InitAnalysisConfig {
            cross_file_output_params,
            ..Default::default()
        };

        let result =
            analyze_init_states_with_statics(&cfg, &func, code, &InitStateMap::new(), &config);
        let use_pos = code.find("parse.keyname").unwrap();
        let info =
            get_var_info_at_with_config(&result, &cfg, &body, code, "parse", use_pos, &config);
        assert!(info.is_some());
        assert!(
            !info.unwrap().state.is_unsafe(),
            "parse should be Initialized via the cross-file output-param call, even though the call sits inside an if-condition and 'parse' is a plain top-level declaration"
        );
    }

    #[test]
    fn test_cross_file_output_params_additive_not_short_circuit() {
        // A call recognized by cross_file_output_params for ONE param must not
        // suppress the pre-existing permissive fallback (process_unknown_function_call)
        // for OTHER params of the same call that the flow-insensitive summary
        // missed -- regression coverage for the short-circuit bug caught while
        // building this fix (short-circuiting dropped coverage and increased
        // hostap EXP33-C findings 1946->1984 before being made additive).
        let code = r#"
        void foo(void) {
            int a, b;
            writer(&a, &b);
            use(a);
            use(b);
        }
        "#;
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let func = tree.root_node().child(0).unwrap();
        let body = func.child_by_field_name("body").unwrap();
        let cfg = build_function_cfg(&func, code).unwrap();

        // Summary only knows about param 0 ("a"); param 1 ("b") is undercounted
        // by the flow-insensitive text scan, same as a real-world miss.
        let mut cross_file_output_params = HashMap::new();
        cross_file_output_params.insert("writer".to_string(), HashSet::from([0usize]));
        let config = InitAnalysisConfig {
            cross_file_output_params,
            ..Default::default()
        };

        let result =
            analyze_init_states_with_statics(&cfg, &func, code, &InitStateMap::new(), &config);
        let b_use = code.find("use(b)").unwrap();
        let info = get_var_info_at_with_config(&result, &cfg, &body, code, "b", b_use, &config);
        assert!(info.is_some());
        assert!(
            !info.unwrap().state.is_unsafe(),
            "b must still be marked Initialized via process_unknown_function_call's permissive \
             &var fallback, even though the summary only covers param 0"
        );
    }

    #[test]
    fn test_conditional_init_both_branches() {
        let code = r#"
        void foo(int c) {
            int x;
            if (c) {
                x = 1;
            } else {
                x = 2;
            }
            int y = x;
        }
        "#;
        let (cfg, result, source) = analyze_code(code);
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(&source, None).unwrap();
        let func = tree.root_node().child(0).unwrap();
        let body = func.child_by_field_name("body").unwrap();

        // After if/else where both branches assign, x should be Initialized
        let use_pos = source.rfind("x;").unwrap();
        let info = get_var_info_at(&result, &cfg, &body, &source, "x", use_pos);
        assert!(info.is_some());
        assert!(
            !info.unwrap().state.is_unsafe(),
            "x should be initialized after if/else"
        );
    }

    #[test]
    fn test_conditional_init_one_branch() {
        let code = r#"
        void foo(int c) {
            int x;
            if (c) {
                x = 1;
            }
            int y = x;
        }
        "#;
        let (cfg, result, source) = analyze_code(code);
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(&source, None).unwrap();
        let func = tree.root_node().child(0).unwrap();
        let body = func.child_by_field_name("body").unwrap();

        // Only one branch assigns — should be MaybeUninitialized
        let use_pos = source.rfind("x;").unwrap();
        let info = get_var_info_at(&result, &cfg, &body, &source, "x", use_pos);
        assert!(info.is_some());
        assert!(
            info.unwrap().state.is_unsafe(),
            "x should be maybe-uninitialized after if without else"
        );
    }

    #[test]
    fn test_malloc_uninitialized() {
        let code = r#"
        void foo() {
            int *p = malloc(sizeof(int));
            *p = 42;
        }
        "#;
        let (cfg, result, source) = analyze_code(code);
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(&source, None).unwrap();
        let func = tree.root_node().child(0).unwrap();
        let body = func.child_by_field_name("body").unwrap();

        // After malloc, p itself is initialized but content is not
        let deref_pos = source.find("*p = 42").unwrap();
        let info = get_var_info_at(&result, &cfg, &body, &source, "p", deref_pos);
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.state, InitState::MallocUninitialized);
        assert!(!info.state.is_unsafe()); // pointer itself IS initialized
        assert!(info.state.is_content_unsafe()); // content is NOT
    }

    #[test]
    fn test_parameter_initialized() {
        let code = "void foo(int x) { int y = x; }";
        let (cfg, result, source) = analyze_code(code);
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(&source, None).unwrap();
        let func = tree.root_node().child(0).unwrap();
        let body = func.child_by_field_name("body").unwrap();

        let info = get_var_info_at(
            &result,
            &cfg,
            &body,
            &source,
            "x",
            source.find("x;").unwrap(),
        );
        assert!(info.is_some());
        assert!(!info.unwrap().state.is_unsafe());
    }
}
