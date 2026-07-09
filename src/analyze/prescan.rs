use super::const_eval;
use super::context::ProjectContext;
use super::function_summary::{self, FunctionSummary};
use crate::analyze::null_state::NullState;
use crate::parser::CParser;
use crate::progress::ProgressReporter;

use anyhow::Result;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tree_sitter::Node;
use walkdir::WalkDir;

/// All data collected from a single file during the parallel prescan phase.
struct FilePrescanResult {
    known_functions: HashSet<String>,
    header_declared_functions: HashSet<String>,
    function_summaries: HashMap<String, FunctionSummary>,
    call_graph: HashMap<String, HashSet<String>>,
    macro_constants: HashMap<String, i64>,
    macro_aliases: HashMap<String, String>,
    function_macros: HashMap<String, crate::analyze::macro_expand::FunctionMacro>,
    struct_field_types: HashMap<String, HashMap<String, String>>,
    global_constants: HashMap<String, i64>,
    global_var_null_states: HashMap<String, NullState>,
    global_writers: HashMap<String, HashSet<String>>,
    callsite_args: HashMap<String, Vec<Vec<NullState>>>,
    callsite_field_args: HashMap<String, Vec<Vec<HashMap<String, NullState>>>>,
    callsite_pointee_args: HashMap<String, Vec<Vec<NullState>>>,
    callsite_int_args: HashMap<String, Vec<Vec<Option<i64>>>>,
    callsite_buf_args: HashMap<String, Vec<Vec<Option<usize>>>>,
    source_path: Option<PathBuf>,
}

impl FilePrescanResult {
    fn empty() -> Self {
        Self {
            known_functions: HashSet::new(),
            header_declared_functions: HashSet::new(),
            function_summaries: HashMap::new(),
            call_graph: HashMap::new(),
            macro_constants: HashMap::new(),
            macro_aliases: HashMap::new(),
            function_macros: HashMap::new(),
            struct_field_types: HashMap::new(),
            global_constants: HashMap::new(),
            global_var_null_states: HashMap::new(),
            global_writers: HashMap::new(),
            callsite_args: HashMap::new(),
            callsite_field_args: HashMap::new(),
            callsite_pointee_args: HashMap::new(),
            callsite_int_args: HashMap::new(),
            callsite_buf_args: HashMap::new(),
            source_path: None,
        }
    }
}

fn process_file(file_path: &Path, is_header: bool, needs_vra: bool) -> FilePrescanResult {
    let mut result = FilePrescanResult::empty();

    let mut parser = match CParser::new() {
        Ok(p) => p,
        Err(_) => return result,
    };

    if let Ok((tree, source)) = parser.parse_file(&file_path.to_string_lossy()) {
        let root = tree.root_node();

        collect_function_names(&root, &source, &mut result.known_functions);

        if is_header {
            collect_header_declarations(&root, &source, &mut result.header_declared_functions);
        }

        let file_macros = const_eval::collect_macro_constants(&root, &source);
        result.macro_constants.extend(file_macros.clone());

        let file_aliases = const_eval::collect_macro_aliases(&root, &source);
        let file_taint_aliases: Vec<String> = file_aliases
            .iter()
            .filter(|(_, target)| {
                function_summary::ENV03_TAINT_SOURCE_FUNCTIONS.contains(&target.as_str())
            })
            .map(|(alias, _)| alias.clone())
            .collect();

        let file_string_macros = const_eval::collect_string_literal_macros(&root, &source);

        result.function_summaries = function_summary::compute_summaries(
            &root,
            &source,
            &file_macros,
            needs_vra,
            &file_taint_aliases,
            &file_string_macros,
        );

        collect_call_graph(&root, &source, &mut result.call_graph);

        result.macro_aliases.extend(file_aliases);

        result.function_macros =
            crate::analyze::macro_expand::collect_function_macros(&root, &source);

        collect_struct_definitions(&root, &source, &mut result.struct_field_types);

        collect_global_constants(&root, &source, &mut result.global_constants);
        collect_constant_return_functions(&root, &source, &mut result.global_constants);

        if !is_header {
            collect_global_var_null_states(&root, &source, &mut result.global_var_null_states);

            let mut file_statics: HashSet<String> = HashSet::new();
            collect_static_pointer_globals(&root, &source, &mut file_statics);
            collect_global_writers(&root, &source, &file_statics, &mut result.global_writers);

            collect_callsite_args_from_tree(
                &root,
                &source,
                &mut result.callsite_args,
                &mut result.callsite_field_args,
                &mut result.callsite_pointee_args,
            );
            collect_callsite_int_args_from_tree(&root, &source, &mut result.callsite_int_args);
            collect_callsite_buf_args_from_tree(&root, &source, &mut result.callsite_buf_args);
            result.source_path = Some(file_path.to_path_buf());
        }
    }

    result
}

/// Pre-scan the given directories to collect function names and summaries from `.c`/`.h` files.
///
/// This provides cross-file context so that rules like DCL31-C and DCL07-C
/// can suppress false positives for functions defined in other translation units.
/// Function summaries enable inter-procedural analysis (e.g., knowing if a callee
/// can return NULL, frees a parameter, or never returns).
pub fn prescan_directories(
    dirs: &[String],
    progress: Option<&dyn ProgressReporter>,
    needs_vra: bool,
) -> Result<ProjectContext> {
    // Phase 1: collect all file paths (sequential — WalkDir is not parallel-safe)
    let mut all_files: Vec<(PathBuf, bool)> = Vec::new();
    for dir in dirs {
        for entry in WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                matches!(
                    e.path().extension().and_then(|ext| ext.to_str()),
                    Some("c") | Some("h")
                )
            })
        {
            let is_header = entry.path().extension().and_then(|ext| ext.to_str()) == Some("h");
            all_files.push((entry.path().to_path_buf(), is_header));
        }
    }

    if let Some(reporter) = progress {
        reporter.report_prescan_start(dirs.len());
    }

    // Phase 2: parse and collect per-file data in parallel
    let file_results: Vec<FilePrescanResult> = all_files
        .par_iter()
        .map(|(path, is_header)| process_file(path, *is_header, needs_vra))
        .collect();

    // Phase 3: merge results sequentially
    let mut known_functions: HashSet<String> = HashSet::new();
    let mut header_declared_functions: HashSet<String> = HashSet::new();
    let mut function_summaries: HashMap<String, FunctionSummary> = HashMap::new();
    let mut call_graph: HashMap<String, HashSet<String>> = HashMap::new();
    let mut macro_constants: HashMap<String, i64> = HashMap::new();
    let mut macro_aliases: HashMap<String, String> = HashMap::new();
    let mut function_macros: HashMap<String, crate::analyze::macro_expand::FunctionMacro> =
        HashMap::new();
    let mut struct_field_types: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut global_constants: HashMap<String, i64> = HashMap::new();
    let mut global_var_null_states: HashMap<String, NullState> = HashMap::new();
    let mut global_writers: HashMap<String, HashSet<String>> = HashMap::new();
    let mut callsite_args: HashMap<String, Vec<Vec<NullState>>> = HashMap::new();
    let mut callsite_field_args: HashMap<String, Vec<Vec<HashMap<String, NullState>>>> =
        HashMap::new();
    let mut callsite_pointee_args: HashMap<String, Vec<Vec<NullState>>> = HashMap::new();
    let mut callsite_int_args: HashMap<String, Vec<Vec<Option<i64>>>> = HashMap::new();
    let mut callsite_buf_args: HashMap<String, Vec<Vec<Option<usize>>>> = HashMap::new();
    let mut source_files: Vec<PathBuf> = Vec::new();
    let mut file_functions: HashMap<PathBuf, Vec<String>> = HashMap::new();

    for r in file_results {
        known_functions.extend(r.known_functions);
        header_declared_functions.extend(r.header_declared_functions);

        if let Some(path) = &r.source_path {
            file_functions
                .entry(path.clone())
                .or_default()
                .extend(r.function_summaries.keys().cloned());
        }

        // OR-merge taint/summary bits; first definition wins for all other fields
        for (name, summary) in r.function_summaries {
            match function_summaries.get_mut(&name) {
                Some(existing) => {
                    existing.has_env03_taint_source |= summary.has_env03_taint_source;
                    existing.returns_tainted |= summary.returns_tainted;
                    existing.has_relative_command_write |= summary.has_relative_command_write;
                    existing
                        .returns_from_callees
                        .extend(summary.returns_from_callees);
                }
                None => {
                    function_summaries.insert(name, summary);
                }
            }
        }

        for (caller, callees) in r.call_graph {
            call_graph.entry(caller).or_default().extend(callees);
        }

        macro_constants.extend(r.macro_constants);
        macro_aliases.extend(r.macro_aliases);
        for (name, m) in r.function_macros {
            function_macros.entry(name).or_insert(m);
        }
        struct_field_types.extend(r.struct_field_types);
        global_constants.extend(r.global_constants);
        global_var_null_states.extend(r.global_var_null_states);

        for (var, writers) in r.global_writers {
            global_writers.entry(var).or_default().extend(writers);
        }
        for (callee, args) in r.callsite_args {
            callsite_args.entry(callee).or_default().extend(args);
        }
        for (callee, args) in r.callsite_field_args {
            callsite_field_args.entry(callee).or_default().extend(args);
        }
        for (callee, args) in r.callsite_pointee_args {
            callsite_pointee_args
                .entry(callee)
                .or_default()
                .extend(args);
        }
        for (callee, args) in r.callsite_int_args {
            callsite_int_args.entry(callee).or_default().extend(args);
        }
        for (callee, args) in r.callsite_buf_args {
            callsite_buf_args.entry(callee).or_default().extend(args);
        }

        if let Some(path) = r.source_path {
            source_files.push(path);
        }
    }

    // Phase 4: post-processing passes (require fully-merged data, stay sequential)

    aggregate_callsite_null_states(
        &callsite_args,
        &mut function_summaries,
        &header_declared_functions,
    );

    aggregate_callsite_field_null_states(&callsite_field_args, &mut function_summaries);

    aggregate_callsite_pointee_null_states(&callsite_pointee_args, &mut function_summaries);

    aggregate_callsite_int_args(
        &callsite_int_args,
        &mut function_summaries,
        &header_declared_functions,
    );

    aggregate_callsite_buf_args(
        &callsite_buf_args,
        &mut function_summaries,
        &header_declared_functions,
    );
    let mut parser = CParser::new()?;
    propagate_param_null_states(
        &source_files,
        &mut parser,
        &mut function_summaries,
        &mut callsite_args,
        &header_declared_functions,
    );
    propagate_param_buffer_sizes(
        &source_files,
        &file_functions,
        &mut parser,
        &mut function_summaries,
        &header_declared_functions,
    );

    function_summary::propagate_transitive_frees(&mut function_summaries);
    function_summary::propagate_return_taint(&mut function_summaries);

    if let Some(reporter) = progress {
        reporter.report_prescan_complete(known_functions.len());
    }

    Ok(ProjectContext {
        known_functions,
        header_declared_functions,
        function_summaries,
        call_graph,
        macro_constants,
        macro_aliases,
        function_macros,
        struct_field_types,
        global_constants,
        global_var_null_states,
        global_writers,
    })
}

/// Scan only the `.h` files directly inside `parent_dir` to collect public API
/// function declarations.
///
/// This is a lightweight alternative to [`prescan_directories`] used when sqc
/// is given a single `.c` file with no explicit `-d` directories.  It populates
/// only `header_declared_functions` — the data needed by DCL15-C and DCL19-C to
/// distinguish intentionally-public API from internal helpers.  It intentionally
/// does **not** populate `known_functions`, `function_summaries`, or any other
/// cross-file field, so rules that require those (DCL31-C, EXP34-C, …) continue
/// to require an explicit `-d` flag.
pub fn prescan_sibling_headers(parent_dir: &str) -> Result<ProjectContext> {
    let mut context = ProjectContext::new();
    let mut parser = CParser::new()?;

    for entry in WalkDir::new(parent_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|ext| ext.to_str()) == Some("h"))
    {
        if let Ok((tree, source)) = parser.parse_file(&entry.path().to_string_lossy()) {
            collect_header_declarations(
                &tree.root_node(),
                &source,
                &mut context.header_declared_functions,
            );
        }
    }

    Ok(context)
}

/// Build a [`ProjectContext`] from a single already-parsed tree.
///
/// This is the intra-file equivalent of [`prescan_directories`]: it computes
/// function summaries and call-site null states so that inter-procedural rules
/// (e.g. EXP34-C) can resolve parameter state within one translation unit.
///
/// Used by the generated integration tests when a `.c` file carries the
/// `// sqc-test: prescan` marker.
#[cfg(test)]
pub fn prescan_single_tree(root: &Node, source: &str) -> ProjectContext {
    let macros = const_eval::collect_macro_constants(root, source);
    let aliases = const_eval::collect_macro_aliases(root, source);
    let taint_aliases: Vec<String> = aliases
        .iter()
        .filter(|(_, target)| {
            function_summary::ENV03_TAINT_SOURCE_FUNCTIONS.contains(&target.as_str())
        })
        .map(|(alias, _)| alias.clone())
        .collect();
    let string_macros = const_eval::collect_string_literal_macros(root, source);
    let mut function_summaries = function_summary::compute_summaries(
        root,
        source,
        &macros,
        false,
        &taint_aliases,
        &string_macros,
    );

    let mut callsite_args: HashMap<String, Vec<Vec<NullState>>> = HashMap::new();
    let mut callsite_field_args: HashMap<String, Vec<Vec<HashMap<String, NullState>>>> =
        HashMap::new();
    let mut callsite_pointee_args: HashMap<String, Vec<Vec<NullState>>> = HashMap::new();
    let mut callsite_int_args: HashMap<String, Vec<Vec<Option<i64>>>> = HashMap::new();
    let mut callsite_buf_args: HashMap<String, Vec<Vec<Option<usize>>>> = HashMap::new();
    collect_callsite_args_from_tree(
        root,
        source,
        &mut callsite_args,
        &mut callsite_field_args,
        &mut callsite_pointee_args,
    );
    collect_callsite_int_args_from_tree(root, source, &mut callsite_int_args);
    collect_callsite_buf_args_from_tree(root, source, &mut callsite_buf_args);

    let empty_headers = HashSet::new();
    aggregate_callsite_null_states(&callsite_args, &mut function_summaries, &empty_headers);
    aggregate_callsite_field_null_states(&callsite_field_args, &mut function_summaries);
    aggregate_callsite_pointee_null_states(&callsite_pointee_args, &mut function_summaries);
    aggregate_callsite_int_args(&callsite_int_args, &mut function_summaries, &empty_headers);
    aggregate_callsite_buf_args(&callsite_buf_args, &mut function_summaries, &empty_headers);

    let known_functions: HashSet<String> = function_summaries.keys().cloned().collect();

    let mut struct_field_types = HashMap::new();
    collect_struct_definitions(root, source, &mut struct_field_types);

    let mut file_statics: HashSet<String> = HashSet::new();
    collect_static_pointer_globals(root, source, &mut file_statics);
    let mut global_writers: HashMap<String, HashSet<String>> = HashMap::new();
    collect_global_writers(root, source, &file_statics, &mut global_writers);

    ProjectContext {
        known_functions,
        function_summaries,
        macro_constants: macros,
        function_macros: crate::analyze::macro_expand::collect_function_macros(root, source),
        struct_field_types,
        global_writers,
        ..ProjectContext::default()
    }
}

/// Collect function declarations (prototypes) from a header file.
/// These represent public API functions with intentional external linkage.
fn collect_header_declarations(node: &Node, source: &str, names: &mut HashSet<String>) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "declaration"
                    // Only collect non-static function prototypes
                    if !has_static_specifier(&child, source) => {
                        if let Some(name) = extract_function_name_from_declaration(&child, source) {
                            names.insert(name);
                        }
                    }
                kind if kind.starts_with("preproc_")
                    || kind == "linkage_specification"
                    || kind == "declaration_list" =>
                {
                    collect_header_declarations(&child, source, names);
                }
                _ => {}
            }
        }
    }
}

/// Check if a declaration node has a `static` storage class specifier.
fn has_static_specifier(node: &Node, source: &str) -> bool {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "storage_class_specifier" {
                if let Ok(text) = child.utf8_text(source.as_bytes()) {
                    if text == "static" {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Extract function names from `function_definition` and `declaration` nodes.
///
/// Recurses into all child nodes — not just `preproc_*` blocks — because
/// tree-sitter may misparse files with complex macros (e.g., sqlite's
/// `sqliteInt.h`), burying function definitions inside `ERROR` or
/// `compound_statement` nodes at the top level. Even inside error recovery,
/// tree-sitter correctly identifies `function_definition` nodes.
fn collect_function_names(node: &Node, source: &str, names: &mut HashSet<String>) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "function_definition" => {
                    if let Some(name) = extract_function_name_from_declarator(&child, source) {
                        names.insert(name);
                    }
                }
                "declaration" => {
                    // Only collect if it contains a function_declarator (i.e. a prototype)
                    if let Some(name) = extract_function_name_from_declaration(&child, source) {
                        names.insert(name);
                    }
                }
                "preproc_function_def" => {
                    // Collect function-like macro names so DCL07-C/DCL31-C
                    // don't flag macro invocations as undeclared functions.
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = name_node
                            .utf8_text(source.as_bytes())
                            .unwrap_or("")
                            .to_string();
                        if !name.is_empty() {
                            names.insert(name);
                        }
                    }
                    collect_function_names(&child, source, names);
                }
                _ => {
                    // Recurse into all other nodes (preproc_*, linkage_specification,
                    // ERROR, compound_statement, etc.) to find buried definitions.
                    collect_function_names(&child, source, names);
                }
            }
        }
    }
}

/// Extract function name from a `function_definition` node's declarator.
fn extract_function_name_from_declarator(node: &Node, source: &str) -> Option<String> {
    let declarator = node.child_by_field_name("declarator")?;
    extract_identifier_from_declarator(&declarator, source)
}

/// Extract function name from a `declaration` node if it's a function prototype.
///
/// Handles both direct function declarators (`void foo(...)`) and
/// pointer-returning declarators (`int *foo(...)`) where tree-sitter
/// wraps the function_declarator inside a pointer_declarator.
fn extract_function_name_from_declaration(node: &Node, source: &str) -> Option<String> {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "function_declarator" => {
                    return extract_identifier_from_declarator(&child, source);
                }
                "pointer_declarator" => {
                    // e.g. `ArrayList *ArrayList_New(int a, int b);`
                    // pointer_declarator wraps the function_declarator
                    return extract_func_name_from_nested_declarator(&child, source);
                }
                "init_declarator" => {
                    for j in 0..child.child_count() {
                        if let Some(grandchild) = child.child(j) {
                            if grandchild.kind() == "function_declarator" {
                                return extract_identifier_from_declarator(&grandchild, source);
                            }
                            if grandchild.kind() == "pointer_declarator" {
                                return extract_func_name_from_nested_declarator(
                                    &grandchild,
                                    source,
                                );
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    None
}

/// Recursively search a declarator subtree for a function_declarator
/// and extract its identifier.  Handles chains like
/// `pointer_declarator -> function_declarator -> identifier`.
fn extract_func_name_from_nested_declarator(node: &Node, source: &str) -> Option<String> {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "function_declarator" => {
                    return extract_identifier_from_declarator(&child, source);
                }
                "pointer_declarator" => {
                    return extract_func_name_from_nested_declarator(&child, source);
                }
                _ => {}
            }
        }
    }
    None
}

/// Drill into a declarator tree to find the leaf `identifier`.
fn extract_identifier_from_declarator(node: &Node, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" => {
            let name = node.utf8_text(source.as_bytes()).unwrap_or("").to_string();
            if name.is_empty() {
                None
            } else {
                Some(name)
            }
        }
        "function_declarator" | "pointer_declarator" => {
            let inner = node.child_by_field_name("declarator")?;
            extract_identifier_from_declarator(&inner, source)
        }
        _ => {
            // Fallback: search children for an identifier
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "identifier" {
                        let name = child.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                        if !name.is_empty() {
                            return Some(name);
                        }
                    }
                }
            }
            None
        }
    }
}

/// Build a call graph by walking function definitions and recording call
/// expressions. Delegates to `lang_parsing_substrate::calls`, which handles
/// function-pointer alias resolution (Juliet v65a/b patterns) and the
/// has_error()-gated corruption guard (task 267/296) generically — see that
/// crate's `calls` module docs for the full rationale.
fn collect_call_graph(
    node: &Node,
    source: &str,
    call_graph: &mut HashMap<String, HashSet<String>>,
) {
    for edge in lang_parsing_substrate::calls::call_edges(*node, source) {
        call_graph
            .entry(edge.caller)
            .or_default()
            .insert(edge.callee);
    }
}

// ---------------------------------------------------------------------------
// Second pass: call-site argument null state collection
// ---------------------------------------------------------------------------

/// Aggregate pre-collected callsite argument null states into callee summaries.
///
/// For each callee, joins per-param states across all call sites:
/// - all NotNull → NotNull (safe to skip null check)
/// - any DefinitelyNull → PossiblyNull (mixed callers)
/// - any Unknown → leaves as Unknown (will default to PossiblyNull in analysis)
///
/// Functions declared in headers get an implicit Unknown caller to prevent
/// false NotNull seeding for externally-visible functions.
fn aggregate_callsite_null_states(
    callsite_args: &HashMap<String, Vec<Vec<NullState>>>,
    summaries: &mut HashMap<String, FunctionSummary>,
    header_declared: &HashSet<String>,
) {
    // For header-declared functions, we need a mutable copy to add implicit Unknown entries
    let mut callsite_args = callsite_args.clone();

    // For header-declared functions, add an implicit Unknown arg vector.
    // This prevents false NotNull seeding for externally-visible functions
    // that may be called from code we don't scan.
    for func_name in header_declared {
        if let Some(summary) = summaries.get(func_name) {
            // Count how many params this function has from its summary
            let max_param = summary
                .dereferences_params
                .iter()
                .chain(summary.checks_null_params.iter())
                .chain(summary.frees_params.iter())
                .chain(summary.modifies_params.iter())
                .max()
                .copied()
                .unwrap_or(0);
            if max_param > 0 || !summary.dereferences_params.is_empty() {
                let unknown_args = vec![NullState::Unknown; max_param + 1];
                callsite_args
                    .entry(func_name.clone())
                    .or_default()
                    .push(unknown_args);
            }
        }
    }

    // Count-based voting per-callee per-param.
    //
    // The prescan's local state tracking can't model null checks between
    // assignment and use, so PossiblyNull from prescan has a high false
    // positive rate.  Instead of a lattice join (where one PossiblyNull
    // callsite poisons a parameter used by 50 NotNull callers), we count
    // callsite states and apply:
    //   a) Any DefinitelyNull → PossiblyNull (confirmed NULL flow)
    //   b) Majority PossiblyNull (> NotNull count) → PossiblyNull
    //   c) Otherwise → NotNull (PossiblyNull is noise)
    for (callee_name, arg_vectors) in &callsite_args {
        if let Some(summary) = summaries.get_mut(callee_name) {
            let max_params = arg_vectors.iter().map(|v| v.len()).max().unwrap_or(0);
            for param_idx in 0..max_params {
                let mut null_count: usize = 0;
                let mut possibly_count: usize = 0;
                let mut not_null_count: usize = 0;
                for args in arg_vectors {
                    if let Some(&state) = args.get(param_idx) {
                        match state {
                            NullState::DefinitelyNull => null_count += 1,
                            NullState::PossiblyNull => possibly_count += 1,
                            NullState::NotNull => not_null_count += 1,
                            NullState::Unknown => {} // no contribution
                        }
                    }
                }
                let total_known = null_count + possibly_count + not_null_count;
                if total_known > 0 {
                    let aggregated = if null_count > 0 || possibly_count > not_null_count {
                        NullState::PossiblyNull
                    } else {
                        NullState::NotNull
                    };
                    summary
                        .callsite_param_null_states
                        .insert(param_idx, aggregated);
                }
            }
        }
    }
}

/// Aggregate struct field null states from call sites into function summaries.
///
/// For each callee, aggregates per-field null states across all call sites using
/// the same voting scheme as `aggregate_callsite_null_states`: any DefinitelyNull
/// or majority PossiblyNull → PossiblyNull, otherwise NotNull.
fn aggregate_callsite_field_null_states(
    callsite_field_args: &HashMap<String, Vec<Vec<HashMap<String, NullState>>>>,
    summaries: &mut HashMap<String, FunctionSummary>,
) {
    for (callee_name, call_sites) in callsite_field_args {
        if let Some(summary) = summaries.get_mut(callee_name) {
            // Determine max params across all call sites
            let max_params = call_sites.iter().map(|v| v.len()).max().unwrap_or(0);
            for param_idx in 0..max_params {
                // Collect all field names seen across call sites for this param
                let mut field_counts: HashMap<String, (usize, usize, usize)> = HashMap::new();
                for site in call_sites {
                    if let Some(fields) = site.get(param_idx) {
                        for (field_name, &state) in fields {
                            let entry = field_counts.entry(field_name.clone()).or_insert((0, 0, 0));
                            match state {
                                NullState::DefinitelyNull => entry.0 += 1,
                                NullState::PossiblyNull => entry.1 += 1,
                                NullState::NotNull => entry.2 += 1,
                                NullState::Unknown => {}
                            }
                        }
                    }
                }
                // Aggregate each field
                let mut field_states = HashMap::new();
                for (field_name, (null_count, possibly_count, not_null_count)) in &field_counts {
                    let total = null_count + possibly_count + not_null_count;
                    if total > 0 {
                        let aggregated = if *null_count > 0 || possibly_count > not_null_count {
                            NullState::PossiblyNull
                        } else {
                            NullState::NotNull
                        };
                        field_states.insert(field_name.clone(), aggregated);
                    }
                }
                if !field_states.is_empty() {
                    summary
                        .callsite_param_field_null_states
                        .insert(param_idx, field_states);
                }
            }
        }
    }
}

/// Aggregate pointee null states from address-of arguments at call sites.
///
/// When a caller passes `&data` where `data = NULL`, the pointed-to value is NULL.
/// This function aggregates those pointee states across all call sites using the same
/// voting scheme as `aggregate_callsite_null_states`.
/// Used for variant 63 pointer-to-pointer null propagation across functions.
fn aggregate_callsite_pointee_null_states(
    callsite_pointee_args: &HashMap<String, Vec<Vec<NullState>>>,
    summaries: &mut HashMap<String, FunctionSummary>,
) {
    for (callee_name, call_sites) in callsite_pointee_args {
        if let Some(summary) = summaries.get_mut(callee_name) {
            let max_params = call_sites.iter().map(|v| v.len()).max().unwrap_or(0);
            for param_idx in 0..max_params {
                let mut null_count: usize = 0;
                let mut possibly_count: usize = 0;
                let mut not_null_count: usize = 0;
                for site in call_sites {
                    if let Some(&state) = site.get(param_idx) {
                        match state {
                            NullState::DefinitelyNull => null_count += 1,
                            NullState::PossiblyNull => possibly_count += 1,
                            NullState::NotNull => not_null_count += 1,
                            NullState::Unknown => {}
                        }
                    }
                }
                let total_known = null_count + possibly_count + not_null_count;
                if total_known > 0 {
                    let aggregated = if null_count > 0 || possibly_count > not_null_count {
                        NullState::PossiblyNull
                    } else {
                        NullState::NotNull
                    };
                    summary
                        .callsite_param_pointee_null_states
                        .insert(param_idx, aggregated);
                }
            }
        }
    }
}

/// Aggregate integer constant call-site args into `callsite_param_const_int`.
///
/// For each parameter index, if every call site within the project passes the
/// same integer constant literal, that constant is stored so VRA can narrow the
/// parameter's entry range. Functions visible to external callers (header-declared)
/// are skipped — we can't know what external code passes.
pub(crate) fn aggregate_callsite_int_args(
    callsite_int_args: &HashMap<String, Vec<Vec<Option<i64>>>>,
    summaries: &mut HashMap<String, FunctionSummary>,
    header_declared: &HashSet<String>,
) {
    for (callee_name, call_sites) in callsite_int_args {
        if header_declared.contains(callee_name) {
            continue;
        }
        if let Some(summary) = summaries.get_mut(callee_name) {
            let max_params = call_sites.iter().map(|v| v.len()).max().unwrap_or(0);
            for param_idx in 0..max_params {
                let mut agreed: Option<i64> = None;
                let mut any_site = false;
                let mut disagree = false;
                for site in call_sites {
                    match site.get(param_idx) {
                        Some(Some(v)) => {
                            any_site = true;
                            match agreed {
                                None => agreed = Some(*v),
                                Some(existing) if existing == *v => {}
                                _ => {
                                    disagree = true;
                                    break;
                                }
                            }
                        }
                        Some(None) => {
                            // Non-constant arg — can't narrow
                            disagree = true;
                            break;
                        }
                        None => {}
                    }
                }
                if !disagree && any_site {
                    if let Some(v) = agreed {
                        summary.callsite_param_const_int.insert(param_idx, v);
                    }
                }
            }
        }
    }
}

/// Collect integer constant call-site argument values from a translation unit.
///
/// For each function call, records the constant value (if determinable) for each
/// argument. Tracks local variable assignments (`data = 2`) to resolve identifiers.
pub(crate) fn collect_callsite_int_args_from_tree(
    node: &Node,
    source: &str,
    callsite_int_args: &mut HashMap<String, Vec<Vec<Option<i64>>>>,
) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "function_definition" => {
                    if let Some(body) = child.child_by_field_name("body") {
                        let local_ints = collect_local_var_int_values(&body, source);
                        collect_int_calls_in_node(&body, source, &local_ints, callsite_int_args);
                    }
                }
                kind if kind.starts_with("preproc_") => {
                    collect_callsite_int_args_from_tree(&child, source, callsite_int_args);
                }
                _ => {}
            }
        }
    }
}

/// Collect the last constant integer assignment to each local variable in a function body.
/// Variables passed by address to any call are invalidated (fscanf-style side effects).
fn collect_local_var_int_values(body: &Node, source: &str) -> HashMap<String, i64> {
    let mut result = HashMap::new();
    collect_int_assignments_in_node(body, source, &mut result);
    // Invalidate any variable that appears as &var in a call — it may be written via pointer.
    invalidate_address_taken_vars(body, source, &mut result);
    result
}

/// Remove from `vals` any variable whose address is taken in a call expression (&var).
fn invalidate_address_taken_vars(node: &Node, source: &str, vals: &mut HashMap<String, i64>) {
    if node.kind() == "call_expression" {
        if let Some(args_node) = node.child_by_field_name("arguments") {
            for i in 0..args_node.child_count() {
                if let Some(arg) = args_node.child(i) {
                    // tree-sitter-c uses "pointer_expression" for &var and *var
                    if arg.kind() == "pointer_expression" {
                        let op = arg
                            .child_by_field_name("operator")
                            .or_else(|| arg.child(0))
                            .and_then(|n| n.utf8_text(source.as_bytes()).ok());
                        if op == Some("&") {
                            let operand =
                                arg.child_by_field_name("argument").or_else(|| arg.child(1));
                            if let Some(operand) = operand {
                                if operand.kind() == "identifier" {
                                    let name = operand.utf8_text(source.as_bytes()).unwrap_or("");
                                    vals.remove(name);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            invalidate_address_taken_vars(&child, source, vals);
        }
    }
}

fn collect_int_assignments_in_node(node: &Node, source: &str, vals: &mut HashMap<String, i64>) {
    match node.kind() {
        "assignment_expression" => {
            if let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) {
                if left.kind() == "identifier" {
                    let name = left.utf8_text(source.as_bytes()).unwrap_or("");
                    match parse_int_literal(&right, source) {
                        Some(v) => {
                            vals.insert(name.to_string(), v);
                        }
                        None => {
                            // Non-literal RHS (e.g. LLONG_MAX macro, rand(), fscanf result):
                            // invalidate any earlier constant we tracked for this variable.
                            vals.remove(name);
                        }
                    }
                }
            }
            // Also recurse into RHS
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    collect_int_assignments_in_node(&child, source, vals);
                }
            }
        }
        "init_declarator" => {
            if let (Some(decl), Some(val_node)) = (
                node.child_by_field_name("declarator"),
                node.child_by_field_name("value"),
            ) {
                let name = extract_init_decl_name(&decl, source);
                if !name.is_empty() {
                    if let Some(v) = parse_int_literal(&val_node, source) {
                        vals.insert(name, v);
                    }
                }
            }
        }
        _ => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    collect_int_assignments_in_node(&child, source, vals);
                }
            }
        }
    }
}

/// Parse a tree-sitter node as an integer literal, handling negation.
fn parse_int_literal(node: &Node, source: &str) -> Option<i64> {
    match node.kind() {
        "number_literal" => {
            let text = node.utf8_text(source.as_bytes()).ok()?.trim();
            // Strip common suffixes (UL, LL, U, L)
            let text = text.trim_end_matches(['u', 'U', 'l', 'L']);
            text.parse::<i64>().ok()
        }
        "unary_expression" => {
            // Handle negation: -2
            let op = node
                .child(0)
                .map(|n| n.utf8_text(source.as_bytes()).unwrap_or(""));
            if op == Some("-") {
                if let Some(operand) = node.child(1) {
                    return parse_int_literal(&operand, source).map(|v| -v);
                }
            }
            None
        }
        _ => None,
    }
}

/// Extract the simple identifier name from a declarator node (for init_declarator).
fn extract_init_decl_name(node: &Node, source: &str) -> String {
    match node.kind() {
        "identifier" => node.utf8_text(source.as_bytes()).unwrap_or("").to_string(),
        "pointer_declarator" | "array_declarator" | "function_declarator" => {
            if let Some(inner) = node.child_by_field_name("declarator") {
                extract_init_decl_name(&inner, source)
            } else {
                String::new()
            }
        }
        _ => String::new(),
    }
}

/// Walk call expressions in a function body, recording integer constant args.
fn collect_int_calls_in_node(
    node: &Node,
    source: &str,
    local_ints: &HashMap<String, i64>,
    callsite_int_args: &mut HashMap<String, Vec<Vec<Option<i64>>>>,
) {
    if node.kind() == "call_expression" {
        if let Some(function) = node.child_by_field_name("function") {
            if function.kind() == "identifier" {
                let callee = function.utf8_text(source.as_bytes()).unwrap_or("");
                if !callee.is_empty() {
                    if let Some(args_node) = node.child_by_field_name("arguments") {
                        let mut arg_vals = Vec::new();
                        for i in 0..args_node.child_count() {
                            if let Some(arg) = args_node.child(i) {
                                if matches!(arg.kind(), "," | "(" | ")") {
                                    continue;
                                }
                                let val = if let Some(v) = parse_int_literal(&arg, source) {
                                    Some(v)
                                } else if arg.kind() == "identifier" {
                                    let name = arg.utf8_text(source.as_bytes()).unwrap_or("");
                                    local_ints.get(name).copied().map(Some).unwrap_or(None)
                                } else {
                                    None
                                };
                                arg_vals.push(val);
                            }
                        }
                        if !arg_vals.is_empty() {
                            callsite_int_args
                                .entry(callee.to_string())
                                .or_default()
                                .push(arg_vals);
                        }
                    }
                }
            }
        }
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_int_calls_in_node(&child, source, local_ints, callsite_int_args);
        }
    }
}

/// Aggregate per-call-site buffer-size args into `callsite_param_buffer_size`.
///
/// For each parameter index, the summary records the MINIMUM element-count
/// buffer size only when *every* call site passes a pointer to a statically
/// sized buffer. If any call site passes an unresolvable buffer (a different
/// parameter, a non-constant allocation, an opaque expression) the parameter is
/// left unrecorded so the consuming rule stays conservative. Header-declared
/// functions are skipped — external callers are unknowable, so we cannot prove
/// the minimum over *all* callers.
pub(crate) fn aggregate_callsite_buf_args(
    callsite_buf_args: &HashMap<String, Vec<Vec<Option<usize>>>>,
    summaries: &mut HashMap<String, FunctionSummary>,
    header_declared: &HashSet<String>,
) {
    for (callee_name, call_sites) in callsite_buf_args {
        if header_declared.contains(callee_name) {
            continue;
        }
        if let Some(summary) = summaries.get_mut(callee_name) {
            let max_params = call_sites.iter().map(|v| v.len()).max().unwrap_or(0);
            for param_idx in 0..max_params {
                let mut min_size: Option<usize> = None;
                let mut any_site = false;
                let mut unresolved = false;
                for site in call_sites {
                    match site.get(param_idx) {
                        Some(Some(sz)) => {
                            any_site = true;
                            min_size = Some(min_size.map_or(*sz, |m: usize| m.min(*sz)));
                        }
                        // A call site that passes a non-buffer/unresolvable
                        // argument here means we can't bound this parameter.
                        Some(None) => {
                            unresolved = true;
                            break;
                        }
                        None => {}
                    }
                }
                if !unresolved && any_site {
                    if let Some(sz) = min_size {
                        summary.callsite_param_buffer_size.insert(param_idx, sz);
                    }
                }
            }
        }
    }
}

/// Maximum buffer-size propagation passes. Each pass resolves one additional
/// forwarding hop (`a → b → c …`); Juliet's deepest chain is 5 (variant 54).
const MAX_BUFFER_PROP_PASSES: usize = 6;

/// Propagate parameter buffer sizes through forwarding chains.
///
/// The first aggregation only resolves parameters whose callers pass a *local*
/// buffer. Relay functions (`void mid(char *p) { low(p); }`) forward a parameter
/// whose size is unknown until `mid`'s own callers are resolved. This pass
/// re-collects call-site buffer args with each function's parameters seeded from
/// the sizes proven so far, then re-aggregates — repeating until the bounds
/// stop changing. A fresh re-collection each pass (rather than accumulating)
/// keeps the sound "every caller passes a known buffer" invariant intact.
fn propagate_param_buffer_sizes(
    source_files: &[PathBuf],
    file_functions: &HashMap<PathBuf, Vec<String>>,
    parser: &mut CParser,
    summaries: &mut HashMap<String, FunctionSummary>,
    header_declared: &HashSet<String>,
) {
    // This pass only ever creates a new bound by forwarding an already-bounded
    // parameter onward, so the first propagating edge must already exist: a
    // function whose buffer-bounded parameter index is also a key in its
    // param_passthroughs. If none exists, no later pass can add anything either
    // (new bounds arise only from such edges), so skip the (per-pass, all-files)
    // re-parse entirely. Gating on bare param-forwarding was too broad — most
    // CWE dirs forward *some* parameter, so non-buffer CWEs paid the re-parse
    // for nothing (observed via the task-202 timing metric: non-buffer CWE-78
    // +163s / CWE-190 +54s with zero FP change).
    let has_forwardable_buffer = summaries.values().any(|s| {
        s.callsite_param_buffer_size
            .keys()
            .any(|p| s.param_passthroughs.contains_key(p))
    });
    if !has_forwardable_buffer {
        return;
    }

    for _pass in 0..MAX_BUFFER_PROP_PASSES {
        let seeds: HashMap<String, HashMap<usize, usize>> = summaries
            .iter()
            .filter(|(_, s)| !s.callsite_param_buffer_size.is_empty())
            .map(|(name, s)| (name.clone(), s.callsite_param_buffer_size.clone()))
            .collect();
        if seeds.is_empty() {
            return;
        }

        // Only files defining a seeded (forwarder) function can produce new
        // callsite info this pass: a function whose parameters aren't in
        // `seeds` re-collects byte-identical results to the previous pass, so
        // re-parsing it is wasted work. This is what shrinks the re-parse set
        // for buffer-forwarding-free CWE dirs (task 204).
        let relevant_files: Vec<&PathBuf> = source_files
            .iter()
            .filter(|f| {
                file_functions
                    .get(f.as_path())
                    .is_some_and(|fns| fns.iter().any(|n| seeds.contains_key(n)))
            })
            .collect();

        let mut fresh: HashMap<String, Vec<Vec<Option<usize>>>> = HashMap::new();
        for file_path in relevant_files {
            if let Ok((tree, source)) = parser.parse_file(&file_path.to_string_lossy()) {
                let root = tree.root_node();
                collect_callsite_buf_args_with_param_sizes(&root, &source, &seeds, &mut fresh);
            }
        }

        for summary in summaries.values_mut() {
            summary.callsite_param_buffer_size.clear();
        }
        aggregate_callsite_buf_args(&fresh, summaries, header_declared);

        let converged = summaries.iter().all(|(name, s)| {
            seeds
                .get(name)
                .map(|m| m == &s.callsite_param_buffer_size)
                .unwrap_or(s.callsite_param_buffer_size.is_empty())
        });
        if converged {
            return;
        }
    }
}

/// Like [`collect_callsite_buf_args_from_tree`], but seeds each function's
/// parameters with the buffer sizes proven by a prior pass, so a forwarded
/// parameter (`low(p)`) resolves to the size flowing into `p`.
fn collect_callsite_buf_args_with_param_sizes(
    node: &Node,
    source: &str,
    param_sizes: &HashMap<String, HashMap<usize, usize>>,
    callsite_buf_args: &mut HashMap<String, Vec<Vec<Option<usize>>>>,
) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "function_definition" => {
                    if let Some(body) = child.child_by_field_name("body") {
                        let mut local_bufs = collect_local_buffer_sizes(&body, source);
                        if let Some(func_name) = extract_function_name(&child, source) {
                            if let Some(param_map) = param_sizes.get(&func_name) {
                                let param_names =
                                    function_summary::collect_param_names(&child, source);
                                for (idx, name) in param_names.iter().enumerate() {
                                    if let Some(sz) = param_map.get(&idx) {
                                        // A local declaration/reassignment of the
                                        // same name takes precedence over the seed.
                                        local_bufs.entry(name.clone()).or_insert(*sz);
                                    }
                                }
                            }
                        }
                        collect_buf_calls_in_node(&body, source, &local_bufs, callsite_buf_args);
                    }
                }
                kind if kind.starts_with("preproc_") => {
                    collect_callsite_buf_args_with_param_sizes(
                        &child,
                        source,
                        param_sizes,
                        callsite_buf_args,
                    );
                }
                _ => {}
            }
        }
    }
}

/// Collect per-call-site buffer-size arguments from a translation unit, keyed
/// by callee name. Mirrors [`collect_callsite_int_args_from_tree`] but resolves
/// each argument to the element-count size of the buffer it points at (when
/// known), tracking local array declarations, allocations and pointer aliases.
pub(crate) fn collect_callsite_buf_args_from_tree(
    node: &Node,
    source: &str,
    callsite_buf_args: &mut HashMap<String, Vec<Vec<Option<usize>>>>,
) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "function_definition" => {
                    if let Some(body) = child.child_by_field_name("body") {
                        let local_bufs = collect_local_buffer_sizes(&body, source);
                        collect_buf_calls_in_node(&body, source, &local_bufs, callsite_buf_args);
                    }
                }
                kind if kind.starts_with("preproc_") => {
                    collect_callsite_buf_args_from_tree(&child, source, callsite_buf_args);
                }
                _ => {}
            }
        }
    }
}

/// Build a map of local variable → element-count buffer size for a function
/// body, processing declarations, allocations and pointer aliases in source
/// order (last write wins). Resolves the Juliet caller pattern
/// `p = (char*)ALLOCA(N*sizeof(char)); data = p; sink(data);`.
fn collect_local_buffer_sizes(body: &Node, source: &str) -> HashMap<String, usize> {
    let mut sizes = HashMap::new();
    collect_buf_sizes_in_node(body, source, &mut sizes);
    sizes
}

fn collect_buf_sizes_in_node(node: &Node, source: &str, sizes: &mut HashMap<String, usize>) {
    match node.kind() {
        "declaration" => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    match child.kind() {
                        // `char buf[100];` (no initializer)
                        "array_declarator" => {
                            if let (Some(name), Some(sz)) = (
                                array_declarator_name(&child, source),
                                array_declarator_size(&child, source),
                            ) {
                                sizes.insert(name, sz);
                            }
                        }
                        // `char *p = alloc(...);` or `char buf[100] = "";`
                        "init_declarator" => {
                            if let Some(decl) = child.child_by_field_name("declarator") {
                                let name = extract_init_decl_name(&decl, source);
                                if !name.is_empty() {
                                    let from_array = array_declarator_size(&decl, source);
                                    let from_value = child
                                        .child_by_field_name("value")
                                        .and_then(|v| resolve_buffer_size_expr(&v, source, sizes));
                                    if let Some(sz) = from_array.or(from_value) {
                                        sizes.insert(name, sz);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        "assignment_expression" => {
            if let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) {
                if left.kind() == "identifier" {
                    let name = left.utf8_text(source.as_bytes()).unwrap_or("");
                    if !name.is_empty() {
                        match resolve_buffer_size_expr(&right, source, sizes) {
                            Some(sz) => {
                                sizes.insert(name.to_string(), sz);
                            }
                            // Reassigned from an unknown buffer — drop the alias.
                            None => {
                                sizes.remove(name);
                            }
                        }
                    }
                }
            }
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    collect_buf_sizes_in_node(&child, source, sizes);
                }
            }
        }
        _ => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    collect_buf_sizes_in_node(&child, source, sizes);
                }
            }
        }
    }
}

/// Resolve an expression to the element-count size of the buffer it denotes:
/// an allocation call, a pointer alias to a known buffer, or a cast/paren
/// wrapper around either.
fn resolve_buffer_size_expr(
    node: &Node,
    source: &str,
    sizes: &HashMap<String, usize>,
) -> Option<usize> {
    match node.kind() {
        "identifier" => {
            let name = node.utf8_text(source.as_bytes()).ok()?;
            sizes.get(name).copied()
        }
        "cast_expression" => {
            let value = node.child_by_field_name("value")?;
            resolve_buffer_size_expr(&value, source, sizes)
        }
        "parenthesized_expression" => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if !matches!(child.kind(), "(" | ")") {
                        return resolve_buffer_size_expr(&child, source, sizes);
                    }
                }
            }
            None
        }
        "call_expression" => {
            let function = node.child_by_field_name("function")?;
            if function.kind() != "identifier" {
                return None;
            }
            let callee = function.utf8_text(source.as_bytes()).ok()?;
            if !crate::analyze::buffer_size::ALLOC_FUNCTIONS.contains(&callee) {
                return None;
            }
            let args = node.child_by_field_name("arguments")?;
            // Inner text of the argument list, minus the enclosing parentheses.
            let args_text = args.utf8_text(source.as_bytes()).ok()?;
            let inner = args_text
                .strip_prefix('(')
                .and_then(|s| s.strip_suffix(')'))
                .unwrap_or(args_text);
            crate::analyze::buffer_size::alloc_call_element_count(callee, inner)
        }
        _ => None,
    }
}

/// Extract the variable name from an `array_declarator` (`buf` in `buf[100]`).
fn array_declarator_name(node: &Node, source: &str) -> Option<String> {
    let inner = node.child_by_field_name("declarator")?;
    if inner.kind() == "identifier" {
        Some(inner.utf8_text(source.as_bytes()).ok()?.to_string())
    } else {
        Some(extract_init_decl_name(&inner, source)).filter(|s| !s.is_empty())
    }
}

/// Extract the constant element count from an `array_declarator` size, if the
/// declarator is an array with a compile-time-constant dimension.
fn array_declarator_size(node: &Node, source: &str) -> Option<usize> {
    if node.kind() != "array_declarator" {
        return None;
    }
    let size = node.child_by_field_name("size")?;
    let text = size.utf8_text(source.as_bytes()).ok()?;
    crate::analyze::buffer_size::extract_numeric_value(text)
}

/// Walk call expressions in a function body, recording the element-count buffer
/// size of each pointer argument (or `None` when it cannot be resolved).
fn collect_buf_calls_in_node(
    node: &Node,
    source: &str,
    local_bufs: &HashMap<String, usize>,
    callsite_buf_args: &mut HashMap<String, Vec<Vec<Option<usize>>>>,
) {
    if node.kind() == "call_expression" {
        if let Some(function) = node.child_by_field_name("function") {
            if function.kind() == "identifier" {
                let callee = function.utf8_text(source.as_bytes()).unwrap_or("");
                if !callee.is_empty() {
                    if let Some(args_node) = node.child_by_field_name("arguments") {
                        let mut arg_sizes = Vec::new();
                        for i in 0..args_node.child_count() {
                            if let Some(arg) = args_node.child(i) {
                                if matches!(arg.kind(), "," | "(" | ")") {
                                    continue;
                                }
                                let sz = if arg.kind() == "identifier" {
                                    let name = arg.utf8_text(source.as_bytes()).unwrap_or("");
                                    local_bufs.get(name).copied()
                                } else {
                                    None
                                };
                                arg_sizes.push(sz);
                            }
                        }
                        if !arg_sizes.is_empty() {
                            callsite_buf_args
                                .entry(callee.to_string())
                                .or_default()
                                .push(arg_sizes);
                        }
                    }
                }
            }
        }
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_buf_calls_in_node(&child, source, local_bufs, callsite_buf_args);
        }
    }
}

/// Second pass: propagate parameter null states through relay functions.
///
/// After the first aggregation, each function has `callsite_param_null_states` derived
/// from its direct callers. However, relay functions (which forward parameters to callees
/// without modification) produce Unknown at those call sites because function parameters
/// aren't in `local_states`.
///
/// This pass re-parses source files, seeds each function's parameter names with their
/// aggregated null states, and re-collects callsite args. Then re-aggregates to propagate
/// the states one level deeper through the call chain.
/// Maximum number of propagation passes for relay chain resolution.
/// Each pass resolves one additional hop in the call chain:
///   Pass 1: caller → relay (single hop)
///   Pass 2: caller → relay1 → relay2 (two hops)
///   Pass 3: caller → relay1 → relay2 → relay3 (three hops)
/// Most real-world code has at most 2-3 relay hops.
const MAX_PROPAGATION_PASSES: usize = 3;

fn propagate_param_null_states(
    source_files: &[PathBuf],
    parser: &mut CParser,
    summaries: &mut HashMap<String, FunctionSummary>,
    callsite_args: &mut HashMap<String, Vec<Vec<NullState>>>,
    header_declared: &HashSet<String>,
) {
    for _pass in 0..MAX_PROPAGATION_PASSES {
        // Snapshot the current param null states before re-collection
        let param_states_snapshot: HashMap<String, HashMap<usize, NullState>> = summaries
            .iter()
            .filter(|(_, s)| !s.callsite_param_null_states.is_empty())
            .map(|(name, s)| (name.clone(), s.callsite_param_null_states.clone()))
            .collect();

        // If no functions have param states, nothing to propagate
        if param_states_snapshot.is_empty() {
            return;
        }

        // Re-collect callsite args with parameter state awareness
        let mut new_callsite_args: HashMap<String, Vec<Vec<NullState>>> = HashMap::new();
        let mut new_callsite_field_args: HashMap<String, Vec<Vec<HashMap<String, NullState>>>> =
            HashMap::new();
        let mut new_callsite_pointee_args: HashMap<String, Vec<Vec<NullState>>> = HashMap::new();

        for file_path in source_files {
            if let Ok((tree, source)) = parser.parse_file(&file_path.to_string_lossy()) {
                let root = tree.root_node();
                collect_callsite_args_with_param_states(
                    &root,
                    &source,
                    &param_states_snapshot,
                    &mut new_callsite_args,
                    &mut new_callsite_field_args,
                    &mut new_callsite_pointee_args,
                );
            }
        }

        // Only proceed if this pass found any new information
        if new_callsite_args.is_empty() {
            return;
        }

        // Merge new callsite args into the existing ones
        for (callee, arg_vecs) in new_callsite_args {
            callsite_args.entry(callee).or_default().extend(arg_vecs);
        }

        // Clear old aggregated states and re-aggregate with the merged data
        let prev_states: HashMap<String, HashMap<usize, NullState>> = summaries
            .iter()
            .filter(|(_, s)| !s.callsite_param_null_states.is_empty())
            .map(|(name, s)| (name.clone(), s.callsite_param_null_states.clone()))
            .collect();

        for summary in summaries.values_mut() {
            summary.callsite_param_null_states.clear();
        }
        aggregate_callsite_null_states(callsite_args, summaries, header_declared);

        // Check for convergence: if no param states changed, stop early
        let converged = summaries.iter().all(|(name, s)| {
            let prev = prev_states.get(name);
            match prev {
                Some(prev_map) => *prev_map == s.callsite_param_null_states,
                None => s.callsite_param_null_states.is_empty(),
            }
        });
        if converged {
            return;
        }
    }
}

/// Like `collect_callsite_args_from_tree`, but also seeds function parameters
/// with their aggregated null states from the first pass. This resolves
/// parameter forwarding patterns like `void mid(int *p) { low(p); }`.
fn collect_callsite_args_with_param_states(
    node: &Node,
    source: &str,
    param_states: &HashMap<String, HashMap<usize, NullState>>,
    callsite_args: &mut HashMap<String, Vec<Vec<NullState>>>,
    callsite_field_args: &mut HashMap<String, Vec<Vec<HashMap<String, NullState>>>>,
    callsite_pointee_args: &mut HashMap<String, Vec<Vec<NullState>>>,
) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "function_definition" => {
                    if let Some(body) = child.child_by_field_name("body") {
                        let mut local_states = collect_local_var_states(&body, source);
                        collect_early_return_null_guards(&body, source, &mut local_states);

                        // Extract function name and seed parameter states
                        let func_name = extract_function_name(&child, source);
                        if let Some(func_name) = func_name {
                            if let Some(func_param_states) = param_states.get(&func_name) {
                                // Get parameter names for this function
                                let param_names =
                                    function_summary::collect_param_names(&child, source);
                                for (idx, name) in param_names.iter().enumerate() {
                                    if !name.is_empty() && !local_states.contains_key(name.as_str())
                                    {
                                        // Only seed if the param isn't already in local_states
                                        // (guards and assignments take priority)
                                        if let Some(&state) = func_param_states.get(&idx) {
                                            local_states.insert(name.clone(), state);
                                        }
                                    }
                                }
                            }
                        }

                        collect_calls_with_locals(
                            &body,
                            source,
                            &local_states,
                            callsite_args,
                            callsite_field_args,
                            callsite_pointee_args,
                        );
                    }
                }
                kind if kind.starts_with("preproc_") => {
                    collect_callsite_args_with_param_states(
                        &child,
                        source,
                        param_states,
                        callsite_args,
                        callsite_field_args,
                        callsite_pointee_args,
                    );
                }
                "linkage_specification" => {
                    collect_callsite_args_with_param_states(
                        &child,
                        source,
                        param_states,
                        callsite_args,
                        callsite_field_args,
                        callsite_pointee_args,
                    );
                }
                "declaration_list" => {
                    collect_callsite_args_with_param_states(
                        &child,
                        source,
                        param_states,
                        callsite_args,
                        callsite_field_args,
                        callsite_pointee_args,
                    );
                }
                _ => {}
            }
        }
    }
}

/// Extract the function name from a function_definition node.
fn extract_function_name(func_node: &Node, source: &str) -> Option<String> {
    let declarator = func_node.child_by_field_name("declarator")?;
    extract_func_name_recursive(&declarator, source)
}

fn extract_func_name_recursive(node: &Node, source: &str) -> Option<String> {
    match node.kind() {
        "function_declarator" => {
            if let Some(declarator) = node.child_by_field_name("declarator") {
                let name = declarator.utf8_text(source.as_bytes()).ok()?;
                let name = name.trim();
                // Handle pointer declarators: strip leading *
                let name = name.trim_start_matches('*');
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
            None
        }
        "pointer_declarator" => {
            if let Some(inner) = node.child_by_field_name("declarator") {
                extract_func_name_recursive(&inner, source)
            } else {
                None
            }
        }
        "identifier" => {
            let name = node.utf8_text(source.as_bytes()).ok()?;
            Some(name.trim().to_string())
        }
        _ => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if let Some(name) = extract_func_name_recursive(&child, source) {
                        return Some(name);
                    }
                }
            }
            None
        }
    }
}

/// Walk an AST tree collecting call-site argument null states.
/// For each function definition, first collects local variable assignments
/// to resolve identifier arguments (e.g., `data = NULL; sink(data)` → DefinitelyNull).
fn collect_callsite_args_from_tree(
    node: &Node,
    source: &str,
    callsite_args: &mut HashMap<String, Vec<Vec<NullState>>>,
    callsite_field_args: &mut HashMap<String, Vec<Vec<HashMap<String, NullState>>>>,
    callsite_pointee_args: &mut HashMap<String, Vec<Vec<NullState>>>,
) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "function_definition" => {
                    // Collect local variable states within this function
                    if let Some(body) = child.child_by_field_name("body") {
                        let mut local_states = collect_local_var_states(&body, source);
                        // Detect early-return null guards: `if (p == NULL) return;`
                        // After the guard, p is guaranteed NotNull.
                        collect_early_return_null_guards(&body, source, &mut local_states);
                        collect_calls_with_locals(
                            &body,
                            source,
                            &local_states,
                            callsite_args,
                            callsite_field_args,
                            callsite_pointee_args,
                        );
                    }
                }
                kind if kind.starts_with("preproc_") => {
                    collect_callsite_args_from_tree(
                        &child,
                        source,
                        callsite_args,
                        callsite_field_args,
                        callsite_pointee_args,
                    );
                }
                _ => {}
            }
        }
    }
}

/// Collect simple local variable assignments within a function body.
/// Tracks the *last* assignment to each variable (flow-insensitive, conservative).
/// Only tracks simple patterns: `var = NULL`, `var = "string"`, `var = &x`, `var = func()`.
fn collect_local_var_states(body: &Node, source: &str) -> HashMap<String, NullState> {
    let mut states = HashMap::new();
    collect_assignments_recursive(body, source, &mut states);
    states
}

/// Detect early-return null guard patterns in the function body.
/// Pattern: `if (var == NULL) return;` or `if (!var) return;` — after the guard,
/// var is guaranteed NotNull for the rest of the function.
/// Inserts guarded variables as NotNull into the states map.
fn collect_early_return_null_guards(
    body: &Node,
    source: &str,
    states: &mut HashMap<String, NullState>,
) {
    for i in 0..body.child_count() {
        if let Some(child) = body.child(i) {
            if child.kind() == "if_statement" {
                if let Some(condition) = child.child_by_field_name("condition") {
                    // Check if consequence contains a return statement (early exit)
                    if has_early_return_consequence(&child) {
                        // Extract variable names from null-check condition
                        for var_name in extract_null_checked_vars(&condition, source) {
                            states.insert(var_name, NullState::NotNull);
                        }
                    }
                }
            }
        }
    }
}

/// Check if an if_statement's consequence contains a return/goto/exit.
fn has_early_return_consequence(if_node: &Node) -> bool {
    if let Some(consequence) = if_node.child_by_field_name("consequence") {
        return node_contains_return(&consequence);
    }
    false
}

fn node_contains_return(node: &Node) -> bool {
    if matches!(node.kind(), "return_statement" | "goto_statement") {
        return true;
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if node_contains_return(&child) {
                return true;
            }
        }
    }
    false
}

/// Extract variable names from a null-check condition.
/// Recognizes: `var == NULL`, `NULL == var`, `!var`, `var == 0`, `0 == var`.
fn extract_null_checked_vars(condition: &Node, source: &str) -> Vec<String> {
    let mut vars = Vec::new();
    let cond_text = condition
        .utf8_text(source.as_bytes())
        .unwrap_or("")
        .trim()
        .to_string();
    // Strip outer parens from parenthesized_expression
    let cond_text = if cond_text.starts_with('(') && cond_text.ends_with(')') {
        &cond_text[1..cond_text.len() - 1]
    } else {
        &cond_text
    };

    // Split on || for compound conditions: `if (!a || !b) return;`
    for part in cond_text.split("||") {
        let part = part.trim();
        // Pattern: !var
        if let Some(var) = part.strip_prefix('!') {
            let var = var.trim();
            if is_simple_identifier(var) {
                vars.push(var.to_string());
            }
        }
        // Pattern: var == NULL or var == 0
        else if let Some(pos) = part.find("==") {
            let left = part[..pos].trim();
            let right = part[pos + 2..].trim();
            if (right == "NULL" || right == "0") && is_simple_identifier(left) {
                vars.push(left.to_string());
            } else if (left == "NULL" || left == "0") && is_simple_identifier(right) {
                vars.push(right.to_string());
            }
        }
    }
    vars
}

/// Check if a string is a simple C identifier (no operators, no spaces).
fn is_simple_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_alphanumeric() || c == '_')
        && s.chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
}

/// True when `stmt` is immediately followed (skipping comments) by an
/// unconditional control-flow divergence — `goto`, `return`, `break`, or
/// `continue`. Such a statement's effect does not fall through to the next
/// straight-line statement, so a NULL assignment here is an error/cleanup sink
/// rather than a value that reaches downstream call sites.
fn stmt_diverges_after(stmt: &Node) -> bool {
    let mut sib = stmt.next_sibling();
    while let Some(n) = sib {
        match n.kind() {
            "comment" => sib = n.next_sibling(),
            "goto_statement" | "return_statement" | "break_statement" | "continue_statement" => {
                return true
            }
            _ => return false,
        }
    }
    false
}

fn collect_assignments_recursive(
    node: &Node,
    source: &str,
    states: &mut HashMap<String, NullState>,
) {
    match node.kind() {
        "expression_statement" => collect_assignment_statement(node, source, states),
        "declaration" => collect_declaration_states(node, source, states),
        _ => {}
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_assignments_recursive(&child, source, states);
        }
    }
}

/// Handle an `expression_statement` wrapping an assignment: dispatches on the
/// LHS shape (`var = expr`, `s.field = expr`, `arr[N] = expr`).
fn collect_assignment_statement(
    stmt: &Node,
    source: &str,
    states: &mut HashMap<String, NullState>,
) {
    for i in 0..stmt.child_count() {
        let Some(child) = stmt.child(i) else { continue };
        if child.kind() != "assignment_expression" {
            continue;
        }
        let (Some(left), Some(right)) = (
            child.child_by_field_name("left"),
            child.child_by_field_name("right"),
        ) else {
            continue;
        };
        match left.kind() {
            "identifier" => assign_identifier_state(&left, &right, stmt, source, states),
            "field_expression" => assign_field_state(&left, &right, source, states),
            "subscript_expression" => assign_subscript_state(&left, &right, source, states),
            _ => {}
        }
    }
}

/// Track plain-variable assignments: `var = expr`.
fn assign_identifier_state(
    left: &Node,
    right: &Node,
    stmt: &Node,
    source: &str,
    states: &mut HashMap<String, NullState>,
) {
    let var_name = left.utf8_text(source.as_bytes()).unwrap_or("").to_string();
    if var_name.is_empty() {
        return;
    }
    let state = infer_rhs_null_state(right, source);
    // An error/cleanup assignment to NULL whose statement is immediately
    // followed by a divergent jump (`x = 0; goto err;`) never falls through
    // to subsequent call sites. Recording it would let the flow-insensitive
    // last-write poison a callee parameter that all reachable callers
    // actually pass non-null (e.g. sqlite whereOmitNoopJoin / growOp3). The
    // malloc-then-deref FN (`p = malloc(); sink(p);`) has no trailing jump,
    // so it is unaffected.
    let is_dead_end_null = matches!(state, NullState::DefinitelyNull | NullState::PossiblyNull)
        && stmt_diverges_after(stmt);
    if state != NullState::Unknown && !is_dead_end_null {
        states.insert(var_name, state);
    }
}

/// Track struct field assignments: `myStruct.field = expr` (variant 67
/// cross-function struct field null propagation), including identifier
/// relays (`myStruct.field = data`).
fn assign_field_state(
    left: &Node,
    right: &Node,
    source: &str,
    states: &mut HashMap<String, NullState>,
) {
    let (Some(base), Some(field)) = (
        left.child_by_field_name("argument"),
        left.child_by_field_name("field"),
    ) else {
        return;
    };
    if base.kind() != "identifier" {
        return;
    }
    let base_name = base.utf8_text(source.as_bytes()).unwrap_or("");
    let field_name = field.utf8_text(source.as_bytes()).unwrap_or("");
    if base_name.is_empty() || field_name.is_empty() {
        return;
    }
    let key = format!("{}.{}", base_name, field_name);
    insert_state_or_relay(&key, right, source, states);
}

/// Track array element assignments: `arr[idx] = expr` (variant 66
/// cross-function array element null propagation). Stored as "arr.idx" in
/// `states` (reuses the field dotted-key mechanism).
fn assign_subscript_state(
    left: &Node,
    right: &Node,
    source: &str,
    states: &mut HashMap<String, NullState>,
) {
    let (Some(arg), Some(idx)) = (
        left.child_by_field_name("argument"),
        left.child_by_field_name("index"),
    ) else {
        return;
    };
    if arg.kind() != "identifier" || idx.kind() != "number_literal" {
        return;
    }
    let arr_name = arg.utf8_text(source.as_bytes()).unwrap_or("");
    let idx_text = idx.utf8_text(source.as_bytes()).unwrap_or("");
    if arr_name.is_empty() || idx_text.is_empty() {
        return;
    }
    let key = format!("{}.{}", arr_name, idx_text);
    insert_state_or_relay(&key, right, source, states);
}

/// Insert the RHS-inferred null state under `key`, or (if the RHS is itself
/// an already-tracked identifier) relay that identifier's known state.
fn insert_state_or_relay(
    key: &str,
    right: &Node,
    source: &str,
    states: &mut HashMap<String, NullState>,
) {
    let state = infer_rhs_null_state(right, source);
    if state != NullState::Unknown {
        states.insert(key.to_string(), state);
    } else if right.kind() == "identifier" {
        let rhs_name = right.utf8_text(source.as_bytes()).unwrap_or("");
        if let Some(&local_state) = states.get(rhs_name) {
            states.insert(key.to_string(), local_state);
        }
    }
}

/// Handle a `declaration` node: init declarators and stack-array
/// declarations (which can never be null).
fn collect_declaration_states(node: &Node, source: &str, states: &mut HashMap<String, NullState>) {
    // Handle `type *var = expr;` init declarations
    if let Some(decl) = node.child_by_field_name("declarator") {
        extract_init_state(&decl, source, states);
    }
    // Also check for multiple declarators and array declarations
    for i in 0..node.child_count() {
        let Some(child) = node.child(i) else { continue };
        if child.kind() == "init_declarator" {
            extract_init_state(&child, source, states);
        }
        // Stack arrays can never be null — mark as NotNull
        if child.kind() == "array_declarator" {
            let var_name = extract_leaf_id(&child, source);
            if !var_name.is_empty() {
                states.insert(var_name, NullState::NotNull);
            }
        }
    }
}

/// Extract null state from an init_declarator: `*var = expr` or `var = expr`.
fn extract_init_state(decl: &Node, source: &str, states: &mut HashMap<String, NullState>) {
    if let Some(value) = decl.child_by_field_name("value") {
        // Find the variable name in the declarator
        let name_node = decl.child_by_field_name("declarator").unwrap_or(*decl);
        let var_name = extract_leaf_id(&name_node, source);
        if !var_name.is_empty() {
            let state = infer_rhs_null_state(&value, source);
            if state != NullState::Unknown {
                states.insert(var_name, state);
            }
        }
    }
}

/// Extract the leaf identifier from a declarator chain.
fn extract_leaf_id(node: &Node, source: &str) -> String {
    match node.kind() {
        "identifier" => node.utf8_text(source.as_bytes()).unwrap_or("").to_string(),
        "pointer_declarator" | "array_declarator" => {
            if let Some(inner) = node.child_by_field_name("declarator") {
                extract_leaf_id(&inner, source)
            } else {
                String::new()
            }
        }
        _ => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "identifier" {
                        return child.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                    }
                }
            }
            String::new()
        }
    }
}

/// Infer null state of a right-hand-side expression in an assignment.
fn infer_rhs_null_state(node: &Node, source: &str) -> NullState {
    // Delegate to the existing literal-level inference first
    let literal_state = function_summary::infer_arg_null_state(node, source);
    if literal_state != NullState::Unknown {
        return literal_state;
    }

    // Additional patterns for RHS:
    match node.kind() {
        "call_expression" => {
            // malloc/calloc/realloc can return NULL → PossiblyNull
            if let Some(func) = node.child_by_field_name("function") {
                let func_name = func.utf8_text(source.as_bytes()).unwrap_or("");
                if matches!(
                    func_name,
                    "malloc" | "calloc" | "realloc" | "aligned_alloc" | "strdup" | "strndup"
                ) {
                    return NullState::PossiblyNull;
                }
            }
            NullState::Unknown
        }
        _ => NullState::Unknown,
    }
}

/// Walk call expressions within a function body, using local variable states
/// to resolve identifier arguments.
fn collect_calls_with_locals(
    node: &Node,
    source: &str,
    local_states: &HashMap<String, NullState>,
    callsite_args: &mut HashMap<String, Vec<Vec<NullState>>>,
    callsite_field_args: &mut HashMap<String, Vec<Vec<HashMap<String, NullState>>>>,
    callsite_pointee_args: &mut HashMap<String, Vec<Vec<NullState>>>,
) {
    if node.kind() == "call_expression" {
        collect_call_expression_locals(
            node,
            source,
            local_states,
            callsite_args,
            callsite_field_args,
            callsite_pointee_args,
        );
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_calls_with_locals(
                &child,
                source,
                local_states,
                callsite_args,
                callsite_field_args,
                callsite_pointee_args,
            );
        }
    }
}

/// Record per-argument null/field/pointee states for a single call site,
/// keyed by callee name.
fn collect_call_expression_locals(
    call: &Node,
    source: &str,
    local_states: &HashMap<String, NullState>,
    callsite_args: &mut HashMap<String, Vec<Vec<NullState>>>,
    callsite_field_args: &mut HashMap<String, Vec<Vec<HashMap<String, NullState>>>>,
    callsite_pointee_args: &mut HashMap<String, Vec<Vec<NullState>>>,
) {
    let Some(function) = call.child_by_field_name("function") else {
        return;
    };
    if function.kind() != "identifier" {
        return;
    }
    let callee_name = function.utf8_text(source.as_bytes()).unwrap_or("");
    if callee_name.is_empty() {
        return;
    }
    let Some(args_node) = call.child_by_field_name("arguments") else {
        return;
    };

    let mut arg_states = Vec::new();
    let mut arg_field_states = Vec::new();
    let mut arg_pointee_states = Vec::new();
    let mut has_field_states = false;
    let mut has_pointee_states = false;
    for i in 0..args_node.child_count() {
        let Some(arg) = args_node.child(i) else {
            continue;
        };
        if matches!(arg.kind(), "," | "(" | ")") {
            continue;
        }
        arg_states.push(infer_call_arg_state(&arg, source, local_states));

        // Collect struct field null states for this argument
        let fields = collect_arg_field_states(&arg, source, local_states);
        has_field_states |= !fields.is_empty();
        arg_field_states.push(fields);

        // Track pointee null state for &var arguments (variant 63).
        // When caller passes &data where data=NULL, the pointee is NULL.
        let pointee = extract_address_of_pointee_state(&arg, source, local_states);
        has_pointee_states |= pointee != NullState::Unknown;
        arg_pointee_states.push(pointee);
    }
    if !arg_states.is_empty() {
        callsite_args
            .entry(callee_name.to_string())
            .or_default()
            .push(arg_states);
    }
    if has_field_states {
        callsite_field_args
            .entry(callee_name.to_string())
            .or_default()
            .push(arg_field_states);
    }
    if has_pointee_states {
        callsite_pointee_args
            .entry(callee_name.to_string())
            .or_default()
            .push(arg_pointee_states);
    }
}

/// Infer a call argument's null state: literal-level inference first, then
/// fall back to the local-variable state table for plain identifiers.
fn infer_call_arg_state(
    arg: &Node,
    source: &str,
    local_states: &HashMap<String, NullState>,
) -> NullState {
    let state = function_summary::infer_arg_null_state(arg, source);
    if state != NullState::Unknown {
        return state;
    }
    if arg.kind() == "identifier" {
        let name = arg.utf8_text(source.as_bytes()).unwrap_or("");
        return local_states
            .get(name)
            .copied()
            .unwrap_or(NullState::Unknown);
    }
    NullState::Unknown
}

/// Collect known struct-field null states (`arg.field`) for an identifier
/// argument, keyed by bare field name.
fn collect_arg_field_states(
    arg: &Node,
    source: &str,
    local_states: &HashMap<String, NullState>,
) -> HashMap<String, NullState> {
    let mut fields = HashMap::new();
    if arg.kind() == "identifier" {
        let arg_name = arg.utf8_text(source.as_bytes()).unwrap_or("");
        let prefix = format!("{}.", arg_name);
        for (key, &st) in local_states {
            if let Some(field_name) = key.strip_prefix(&prefix) {
                fields.insert(field_name.to_string(), st);
            }
        }
    }
    fields
}

/// Extract pointee null state from an address-of argument.
/// For `&data`, looks up `data` in local_states and returns its null state.
/// Returns Unknown if the argument is not an address-of expression.
fn extract_address_of_pointee_state(
    arg: &Node,
    source: &str,
    local_states: &HashMap<String, NullState>,
) -> NullState {
    // tree-sitter-c represents &x as pointer_expression or unary_expression
    let is_addr_of = (arg.kind() == "pointer_expression" || arg.kind() == "unary_expression")
        && arg
            .child_by_field_name("operator")
            .map(|op| op.utf8_text(source.as_bytes()).unwrap_or("") == "&")
            .unwrap_or(false);
    if !is_addr_of {
        return NullState::Unknown;
    }
    if let Some(inner) = arg.child_by_field_name("argument") {
        if inner.kind() == "identifier" {
            let inner_name = inner.utf8_text(source.as_bytes()).unwrap_or("");
            if let Some(&state) = local_states.get(inner_name) {
                return state;
            }
        }
    }
    // For unary_expression, the operand field may be named differently
    if arg.kind() == "unary_expression" {
        if let Some(inner) = arg.child(1) {
            if inner.kind() == "identifier" {
                let inner_name = inner.utf8_text(source.as_bytes()).unwrap_or("");
                if let Some(&state) = local_states.get(inner_name) {
                    return state;
                }
            }
        }
    }
    NullState::Unknown
}

// ---------------------------------------------------------------------------
// Struct field type collection
// ---------------------------------------------------------------------------

/// Collect null states for file-scope non-static, non-extern pointer globals.
///
/// Finds declarations like `char *globalData;` or `char *globalData = NULL;`
/// at file scope, then walks all function bodies for assignments to those
/// globals. Tracks the common Juliet pattern: `data = NULL; globalVar = data;`.
///
/// Results are joined into the provided `states` map across all files.
/// Used by EXP34-C for cross-file variant 68 detection.
fn collect_global_var_null_states(
    root: &Node,
    source: &str,
    states: &mut HashMap<String, NullState>,
) {
    use crate::analyze::null_state;

    // Step 1: Find file-scope pointer globals (non-static, non-extern).
    let mut global_vars: HashSet<String> = HashSet::new();
    collect_prescan_pointer_globals(root, source, &mut global_vars, states);

    if global_vars.is_empty() {
        return;
    }

    // Step 2: Walk function bodies for assignments to these globals.
    for i in 0..root.child_count() {
        let child = match root.child(i) {
            Some(c) => c,
            None => continue,
        };
        match child.kind() {
            "function_definition" => {
                if let Some(body) = child.child_by_field_name("body") {
                    scan_global_var_assignments(&body, source, &global_vars, states);
                }
            }
            k if k.starts_with("preproc_") => {
                // Recurse into preprocessor blocks for nested function definitions
                scan_preproc_for_functions(&child, source, &global_vars, states);
            }
            _ => {}
        }
    }

    fn scan_preproc_for_functions(
        node: &Node,
        source: &str,
        global_vars: &HashSet<String>,
        states: &mut HashMap<String, NullState>,
    ) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "function_definition" => {
                        if let Some(body) = child.child_by_field_name("body") {
                            scan_global_var_assignments(&body, source, global_vars, states);
                        }
                    }
                    k if k.starts_with("preproc_") => {
                        scan_preproc_for_functions(&child, source, global_vars, states);
                    }
                    _ => {}
                }
            }
        }
    }

    /// Classify an RHS expression as a NullState for prescan purposes.
    fn classify_rhs(node: &Node, source: &str) -> NullState {
        let text = node
            .utf8_text(source.as_bytes())
            .unwrap_or("")
            .trim()
            .to_string();
        if null_state::is_null_value(&text) {
            return NullState::DefinitelyNull;
        }
        // Cast to NULL: (type*)NULL or (type*)0
        if node.kind() == "cast_expression" {
            if let Some(value) = node.child_by_field_name("value") {
                let vt = value
                    .utf8_text(source.as_bytes())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if null_state::is_null_value(&vt) {
                    return NullState::DefinitelyNull;
                }
            }
        }
        // String literal → NotNull
        if node.kind() == "string_literal" {
            return NullState::NotNull;
        }
        // Address-of → NotNull
        if node.kind() == "pointer_expression" {
            if let Some(op) = node.child_by_field_name("operator") {
                if op.utf8_text(source.as_bytes()).unwrap_or("") == "&" {
                    return NullState::NotNull;
                }
            }
        }
        NullState::NotNull
    }

    /// Recursively scan a function body for assignments to global pointer vars.
    /// Handles `data = NULL; globalVar = data;` relay pattern.
    fn scan_global_var_assignments(
        node: &Node,
        source: &str,
        global_vars: &HashSet<String>,
        states: &mut HashMap<String, NullState>,
    ) {
        if node.kind() == "assignment_expression" {
            if let Some(left) = node.child_by_field_name("left") {
                let var_name = left.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                if global_vars.contains(&var_name) {
                    if let Some(right) = node.child_by_field_name("right") {
                        let new_state = if right.kind() == "identifier" {
                            let rhs_text =
                                right.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                            if null_state::is_null_value(&rhs_text) {
                                NullState::DefinitelyNull
                            } else {
                                // Check preceding statement for relay pattern:
                                //   data = NULL; globalVar = data;
                                check_preceding_assign_state(node, &rhs_text, source)
                            }
                        } else {
                            classify_rhs(&right, source)
                        };
                        let existing = states.get(&var_name).copied().unwrap_or(NullState::Unknown);
                        states.insert(var_name, existing.join(new_state));
                    }
                }
            }
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                scan_global_var_assignments(&child, source, global_vars, states);
            }
        }
    }

    /// Check the preceding statement for a null/non-null assignment to the
    /// relay variable. Handles: `data = NULL; globalVar = data;`
    fn check_preceding_assign_state(
        assignment_node: &Node,
        var_name: &str,
        source: &str,
    ) -> NullState {
        let expr_stmt = match assignment_node.parent() {
            Some(p) if p.kind() == "expression_statement" => p,
            _ => return NullState::Unknown,
        };
        if let Some(prev) = expr_stmt.prev_sibling() {
            // Check expression_statement: `var = EXPR;`
            if prev.kind() == "expression_statement" {
                if let Some(expr) = prev.child(0) {
                    if expr.kind() == "assignment_expression" {
                        if let Some(left) = expr.child_by_field_name("left") {
                            if left.utf8_text(source.as_bytes()).unwrap_or("") == var_name {
                                if let Some(right) = expr.child_by_field_name("right") {
                                    return classify_rhs(&right, source);
                                }
                            }
                        }
                    }
                }
            }
            // Check declaration: `TYPE *var = EXPR;`
            if prev.kind() == "declaration" {
                for i in 0..prev.child_count() {
                    if let Some(child) = prev.child(i) {
                        if child.kind() == "init_declarator" {
                            let name = extract_declarator_name(&child, source);
                            if name == var_name {
                                if let Some(value) = child.child_by_field_name("value") {
                                    return classify_rhs(&value, source);
                                }
                            }
                        }
                    }
                }
            }
        }
        NullState::Unknown
    }
}

/// Find file-scope non-static, non-extern pointer declarations.
fn collect_prescan_pointer_globals(
    node: &Node,
    source: &str,
    global_vars: &mut HashSet<String>,
    states: &mut HashMap<String, NullState>,
) {
    use crate::analyze::null_state;

    for i in 0..node.child_count() {
        let child = match node.child(i) {
            Some(c) => c,
            None => continue,
        };
        match child.kind() {
            "declaration" => {
                // Collect type qualifiers and storage class
                let mut has_extern = false;
                let mut has_static = false;
                let mut has_pointer = false;
                for j in 0..child.child_count() {
                    if let Some(tc) = child.child(j) {
                        if tc.kind() == "storage_class_specifier" {
                            let text = tc.utf8_text(source.as_bytes()).unwrap_or("");
                            if text == "extern" {
                                has_extern = true;
                            }
                            if text == "static" {
                                has_static = true;
                            }
                        }
                        if tc.kind() == "pointer_declarator" || tc.kind() == "init_declarator" {
                            has_pointer = true;
                        }
                    }
                }
                // Skip extern (defined elsewhere) and static (file-local)
                if has_extern || has_static || !has_pointer {
                    continue;
                }
                // Extract pointer declarators with optional initializer
                for j in 0..child.child_count() {
                    if let Some(decl) = child.child(j) {
                        if decl.kind() == "init_declarator" {
                            // Check that it's a pointer type
                            if !has_pointer_in_declarator(&decl) {
                                continue;
                            }
                            let name = extract_declarator_name(&decl, source);
                            if name.is_empty() {
                                continue;
                            }
                            global_vars.insert(name.clone());
                            if let Some(value) = decl.child_by_field_name("value") {
                                let vtext = value
                                    .utf8_text(source.as_bytes())
                                    .unwrap_or("")
                                    .trim()
                                    .to_string();
                                let state = if null_state::is_null_value(&vtext) {
                                    NullState::DefinitelyNull
                                } else {
                                    NullState::NotNull
                                };
                                let existing =
                                    states.get(&name).copied().unwrap_or(NullState::Unknown);
                                states.insert(name, existing.join(state));
                            }
                        } else if decl.kind() == "pointer_declarator" {
                            // Bare pointer declarator without init
                            let name = extract_declarator_name(&decl, source);
                            if !name.is_empty() {
                                global_vars.insert(name);
                                // No initializer — leave as Unknown
                            }
                        }
                    }
                }
            }
            k if k.starts_with("preproc_") => {
                collect_prescan_pointer_globals(&child, source, global_vars, states);
            }
            _ => {}
        }
    }
}

/// Collect names of file-scope `static <type> *<name>[ = ...];` declarations.
/// Narrowed to pointer types because they are the taint-relevant read-site
/// pattern that ENV03-C/ENV33-C watch for (`char *data = g_static;`).
fn collect_static_pointer_globals(node: &Node, source: &str, out: &mut HashSet<String>) {
    for i in 0..node.child_count() {
        let Some(child) = node.child(i) else { continue };
        match child.kind() {
            "declaration" => {
                let mut has_extern = false;
                for j in 0..child.child_count() {
                    if let Some(tc) = child.child(j) {
                        if tc.kind() == "storage_class_specifier"
                            && tc.utf8_text(source.as_bytes()).unwrap_or("") == "extern"
                        {
                            has_extern = true;
                            break;
                        }
                    }
                }
                // Collect file-scope pointer definitions: static (internal linkage) and
                // implicitly-extern (no storage class, external linkage). Skip extern
                // declarations (forward declarations without storage) — they are not
                // definitions, so no writers live in the same TU. This handles both the
                // Juliet v45 pattern (static globals) and the v68 pattern (extern-linkage
                // globals defined in one file and read as extern in another).
                if has_extern {
                    continue;
                }
                for j in 0..child.child_count() {
                    let Some(decl) = child.child(j) else { continue };
                    match decl.kind() {
                        "init_declarator" => {
                            if let Some(inner) = decl.child_by_field_name("declarator") {
                                if inner.kind() == "pointer_declarator" {
                                    let name = extract_declarator_name(&inner, source);
                                    if !name.is_empty() {
                                        out.insert(name);
                                    }
                                }
                            }
                        }
                        "pointer_declarator" => {
                            let name = extract_declarator_name(&decl, source);
                            if !name.is_empty() {
                                out.insert(name);
                            }
                        }
                        _ => {}
                    }
                }
            }
            k if k.starts_with("preproc_") => {
                collect_static_pointer_globals(&child, source, out);
            }
            _ => {}
        }
    }
}

/// For each function definition in `node`, record the function name as a
/// writer of any file-scope static global in `file_globals` that it assigns
/// to (plain `=` assignment with an identifier LHS). Feeds
/// [`ProjectContext::global_writers`] so consumers (ENV03-C) can decide
/// whether a read from the global brings in taint.
fn collect_global_writers(
    node: &Node,
    source: &str,
    file_globals: &HashSet<String>,
    writers: &mut HashMap<String, HashSet<String>>,
) {
    if file_globals.is_empty() {
        return;
    }
    for i in 0..node.child_count() {
        let Some(child) = node.child(i) else { continue };
        match child.kind() {
            "function_definition" => {
                if let Some(func_name) = extract_function_name(&child, source) {
                    if let Some(body) = child.child_by_field_name("body") {
                        scan_body_for_global_writes(
                            &body,
                            source,
                            &func_name,
                            file_globals,
                            writers,
                        );
                    }
                }
            }
            k if k.starts_with("preproc_") => {
                collect_global_writers(&child, source, file_globals, writers);
            }
            _ => {}
        }
    }
}

fn scan_body_for_global_writes(
    node: &Node,
    source: &str,
    func_name: &str,
    file_globals: &HashSet<String>,
    writers: &mut HashMap<String, HashSet<String>>,
) {
    if node.kind() == "assignment_expression" {
        if let Some(left) = node.child_by_field_name("left") {
            if left.kind() == "identifier" {
                let name = left.utf8_text(source.as_bytes()).unwrap_or("");
                if file_globals.contains(name) {
                    writers
                        .entry(name.to_string())
                        .or_default()
                        .insert(func_name.to_string());
                }
            }
        }
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            scan_body_for_global_writes(&child, source, func_name, file_globals, writers);
        }
    }
}

/// Check if a declarator node contains a pointer indicator (`*`).
fn has_pointer_in_declarator(node: &Node) -> bool {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "pointer_declarator" {
                return true;
            }
        }
    }
    false
}

/// Collect global constants (`[const] TYPE NAME = VALUE;`) from file-scope declarations.
/// Only collects non-static constants (static ones are file-local and handled by
/// `init_state::collect_file_scope_constants` within each file).
fn collect_global_constants(root: &Node, source: &str, constants: &mut HashMap<String, i64>) {
    for i in 0..root.child_count() {
        if let Some(child) = root.child(i) {
            match child.kind() {
                "declaration" => {
                    let type_text = {
                        let mut text = String::new();
                        for j in 0..child.child_count() {
                            if let Some(tc) = child.child(j) {
                                if tc.kind() == "storage_class_specifier"
                                    || tc.kind() == "type_qualifier"
                                    || tc.kind() == "primitive_type"
                                    || tc.kind() == "sized_type_specifier"
                                {
                                    if let Ok(t) = tc.utf8_text(source.as_bytes()) {
                                        text.push_str(t);
                                        text.push(' ');
                                    }
                                }
                            }
                        }
                        text
                    };
                    // Skip static declarations (handled per-file in init_state)
                    if type_text.contains("static") {
                        continue;
                    }
                    // Accept: const TYPE NAME = VALUE; or TYPE NAME = VALUE;
                    // (non-const globals are included for benchmark support)
                    for j in 0..child.child_count() {
                        if let Some(decl) = child.child(j) {
                            if decl.kind() == "init_declarator" {
                                let name = extract_declarator_name(&decl, source);
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
                    collect_global_constants(&child, source, constants);
                }
                _ => {}
            }
        }
    }
}

/// Collect non-static zero-argument functions with a single `return LITERAL;` body
/// into the constants map. This enables dead-branch elimination for patterns like
/// `if(globalReturnsTrue())` and `if(globalReturnsFalse())`.
fn collect_constant_return_functions(
    root: &Node,
    source: &str,
    constants: &mut HashMap<String, i64>,
) {
    for i in 0..root.child_count() {
        if let Some(child) = root.child(i) {
            match child.kind() {
                "function_definition" => {
                    collect_one_constant_function(&child, source, constants);
                }
                "preproc_ifdef" | "preproc_if" | "preproc_else" | "preproc_elif"
                | "preproc_ifndef" => {
                    collect_constant_return_functions(&child, source, constants);
                }
                _ => {}
            }
        }
    }
}

fn collect_one_constant_function(
    func_node: &Node,
    source: &str,
    constants: &mut HashMap<String, i64>,
) {
    // Skip static functions (handled per-file by init_state)
    if let Some(type_node) = func_node.child_by_field_name("type") {
        let type_text = type_node.utf8_text(source.as_bytes()).unwrap_or("");
        if type_text.contains("static") {
            return;
        }
    }
    // Check storage class in the declaration specifiers
    for i in 0..func_node.child_count() {
        if let Some(child) = func_node.child(i) {
            if child.kind() == "storage_class_specifier" {
                let text = child.utf8_text(source.as_bytes()).unwrap_or("");
                if text == "static" {
                    return;
                }
            }
        }
    }

    let declarator = match func_node.child_by_field_name("declarator") {
        Some(d) => d,
        None => return,
    };
    let func_decl = match find_func_declarator(&declarator) {
        Some(d) => d,
        None => return,
    };

    // Params must be empty or just "void"
    let params = match func_decl.child_by_field_name("parameters") {
        Some(p) => p,
        None => return,
    };
    let named_count = params.named_child_count();
    if named_count > 1 {
        return;
    }
    if named_count == 1 {
        if let Some(p) = params.named_child(0) {
            let text = p.utf8_text(source.as_bytes()).unwrap_or("");
            if text != "void" {
                return;
            }
        }
    }

    // Get function name
    let name = extract_func_name(&func_decl, source);
    if name.is_empty() {
        return;
    }

    // Body must have exactly one return_statement with a literal value
    let body = match func_node.child_by_field_name("body") {
        Some(b) => b,
        None => return,
    };
    let mut return_val: Option<i64> = None;
    let mut non_return_stmts = 0usize;
    for i in 0..body.child_count() {
        if let Some(stmt) = body.child(i) {
            match stmt.kind() {
                "{" | "}" => {}
                "return_statement" => {
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

    if non_return_stmts == 0 {
        if let Some(val) = return_val {
            constants.insert(name, val);
        }
    }
}

fn find_func_declarator<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    if node.kind() == "function_declarator" {
        return Some(*node);
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if let Some(found) = find_func_declarator(&child) {
                return Some(found);
            }
        }
    }
    None
}

fn extract_func_name(func_decl: &Node, source: &str) -> String {
    for i in 0..func_decl.child_count() {
        if let Some(child) = func_decl.child(i) {
            match child.kind() {
                "identifier" => {
                    return child.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                }
                "pointer_declarator" => {
                    return extract_func_name(&child, source);
                }
                _ => {}
            }
        }
    }
    String::new()
}

/// Extract declarator name from an init_declarator node.
fn extract_declarator_name(decl: &Node, source: &str) -> String {
    for i in 0..decl.child_count() {
        if let Some(child) = decl.child(i) {
            match child.kind() {
                "identifier" => {
                    return child.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                }
                "pointer_declarator" => {
                    return extract_declarator_name(&child, source);
                }
                _ => {}
            }
        }
    }
    String::new()
}

/// Collect struct field types from struct definitions and typedefs.
///
/// Handles three patterns:
/// 1. `struct Name { type field; ... };`
/// 2. `typedef struct { type field; ... } Name;`
/// 3. `typedef struct Name { type field; ... } Name;` (or alias)
fn collect_struct_definitions(
    node: &Node,
    source: &str,
    struct_field_types: &mut HashMap<String, HashMap<String, String>>,
) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "struct_specifier" => {
                    // Pattern 1: `struct Name { ... };` (top-level or inside declaration)
                    collect_from_struct_specifier(&child, source, struct_field_types);
                }
                "type_definition" => {
                    // Pattern 2/3: `typedef struct { ... } Name;`
                    collect_from_typedef(&child, source, struct_field_types);
                }
                "declaration" => {
                    // Struct definitions can appear inside declarations:
                    // `struct Name { ... } var;`
                    for j in 0..child.child_count() {
                        if let Some(gc) = child.child(j) {
                            if gc.kind() == "struct_specifier" {
                                collect_from_struct_specifier(&gc, source, struct_field_types);
                            }
                        }
                    }
                }
                kind if kind.starts_with("preproc_")
                    || kind == "linkage_specification"
                    || kind == "declaration_list" =>
                {
                    collect_struct_definitions(&child, source, struct_field_types);
                }
                _ => {}
            }
        }
    }
}

/// Extract fields from a `struct_specifier` node with a name and body.
fn collect_from_struct_specifier(
    node: &Node,
    source: &str,
    struct_field_types: &mut HashMap<String, HashMap<String, String>>,
) {
    let name = match node.child_by_field_name("name") {
        Some(n) => n.utf8_text(source.as_bytes()).unwrap_or("").to_string(),
        None => return, // Anonymous struct without typedef — can't reference by name
    };
    if name.is_empty() {
        return;
    }
    if let Some(body) = node.child_by_field_name("body") {
        let fields = extract_struct_fields(&body, source);
        if !fields.is_empty() {
            struct_field_types.insert(name, fields);
        }
    }
}

/// Extract fields from a `type_definition` containing a struct specifier.
/// Handles: `typedef struct [Name] { ... } Alias;`
fn collect_from_typedef(
    node: &Node,
    source: &str,
    struct_field_types: &mut HashMap<String, HashMap<String, String>>,
) {
    let mut struct_spec = None;
    let mut typedef_name = None;

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "struct_specifier" {
                struct_spec = Some(child);
            }
            // The typedef alias is a type_identifier at the end
            if child.kind() == "type_identifier" {
                typedef_name = Some(child.utf8_text(source.as_bytes()).unwrap_or("").to_string());
            }
            // Handle pointer typedefs: `typedef struct Foo *FooPtr;`
            if child.kind() == "pointer_declarator" {
                if let Some(inner) = child.child_by_field_name("declarator") {
                    if inner.kind() == "type_identifier" {
                        // Skip pointer typedefs — we want value types only
                    }
                }
            }
        }
    }

    if let Some(spec) = struct_spec {
        // First, collect under the struct's own name (if it has one)
        collect_from_struct_specifier(&spec, source, struct_field_types);

        // Then, also register under the typedef alias
        if let Some(alias) = typedef_name {
            if !alias.is_empty() {
                if let Some(body) = spec.child_by_field_name("body") {
                    let fields = extract_struct_fields(&body, source);
                    if !fields.is_empty() {
                        struct_field_types.insert(alias, fields);
                    }
                }
            }
        }
    }
}

/// Extract field name → type text from a `field_declaration_list` node.
///
/// Anonymous `struct`/`union` members inside the body have their inner fields
/// flattened into the parent, matching C's transparent-access semantics.
fn extract_struct_fields(body: &Node, source: &str) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    for i in 0..body.child_count() {
        if let Some(child) = body.child(i) {
            if child.kind() == "field_declaration" {
                if let Some((field_name, type_text)) = extract_field_decl(&child, source) {
                    fields.insert(field_name, type_text);
                } else if let Some(inner) = find_anonymous_inner_body(&child) {
                    for (k, v) in extract_struct_fields(&inner, source) {
                        fields.insert(k, v);
                    }
                }
            }
        }
    }
    fields
}

/// For an anonymous `union`/`struct` inside a `field_declaration`, return the
/// inner `field_declaration_list`. Returns `None` for named or non-anonymous
/// specifiers — those are treated as typed fields, not flattened.
fn find_anonymous_inner_body<'a>(field_decl: &Node<'a>) -> Option<Node<'a>> {
    for i in 0..field_decl.child_count() {
        let child = field_decl.child(i)?;
        if matches!(child.kind(), "union_specifier" | "struct_specifier")
            && child.child_by_field_name("name").is_none()
        {
            if let Some(body) = child.child_by_field_name("body") {
                return Some(body);
            }
        }
    }
    None
}

/// Extract (field_name, type_text) from a single `field_declaration` node.
///
/// A field_declaration looks like: `type_specifiers declarator ;`
/// e.g., `unsigned int flags;` or `char *name;` or `struct Inner *inner;`
fn extract_field_decl(node: &Node, source: &str) -> Option<(String, String)> {
    // Collect type specifier text (everything before the declarator)
    let mut type_parts = Vec::new();
    let mut field_name = None;
    let mut has_pointer = false;

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "type_qualifier"
                | "primitive_type"
                | "sized_type_specifier"
                | "struct_specifier"
                | "enum_specifier"
                | "union_specifier"
                | "type_identifier" => {
                    type_parts.push(child.utf8_text(source.as_bytes()).unwrap_or("").to_string());
                }
                "field_identifier" => {
                    field_name = Some(child.utf8_text(source.as_bytes()).unwrap_or("").to_string());
                }
                "pointer_declarator" => {
                    has_pointer = true;
                    // Extract field_identifier from inside pointer_declarator
                    field_name = extract_field_id_from_declarator(&child, source);
                }
                "array_declarator" => {
                    // e.g., `char name[64];` — extract field_identifier
                    field_name = extract_field_id_from_declarator(&child, source);
                }
                "function_declarator" => {
                    // Function pointer fields — skip for type resolution purposes
                    return None;
                }
                _ => {}
            }
        }
    }

    let name = field_name?;
    if name.is_empty() || type_parts.is_empty() {
        return None;
    }

    let mut type_text = type_parts.join(" ");
    if has_pointer {
        type_text.push_str(" *");
    }

    Some((name, type_text))
}

/// Extract field_identifier from a declarator chain (pointer_declarator, array_declarator).
fn extract_field_id_from_declarator(node: &Node, source: &str) -> Option<String> {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "field_identifier" => {
                    return Some(child.utf8_text(source.as_bytes()).unwrap_or("").to_string());
                }
                "pointer_declarator" | "array_declarator" => {
                    return extract_field_id_from_declarator(&child, source);
                }
                _ => {}
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Include path resolution (-I flag)
// ---------------------------------------------------------------------------

/// Resolve `#include` directives from source files against the given include
/// search paths, parse found headers, and merge declarations into `context`.
///
/// Each resolved header is parsed only once (deduped by canonical path).
/// Both `"quoted.h"` and `<angle.h>` forms are resolved; unfound system
/// headers are silently skipped.
pub fn resolve_includes(
    source_files: &[String],
    include_paths: &[String],
    context: &mut super::context::ProjectContext,
    progress: Option<&dyn ProgressReporter>,
    needs_vra: bool,
) -> Result<()> {
    if let Some(reporter) = progress {
        reporter.report_include_resolve_start(include_paths.len());
    }

    let mut parser = CParser::new()?;
    let mut resolved_set: HashSet<PathBuf> = HashSet::new();

    // Queue of (include_path, source_dir) pairs to resolve — supports transitive includes
    let mut queue: Vec<(String, Option<PathBuf>)> = Vec::new();

    // Seed the queue with #include directives from source files
    for file_path in source_files {
        if let Ok((tree, source)) = parser.parse_file(file_path) {
            let directives = extract_include_directives(&tree.root_node(), &source);
            let source_dir = Path::new(file_path).parent().map(|p| p.to_path_buf());
            for inc in directives {
                queue.push((inc, source_dir.clone()));
            }
        }
    }

    // Process queue: resolve each header, parse it, and enqueue its transitive includes
    while let Some((include_path, source_dir)) = queue.pop() {
        if let Some(resolved) = resolve_header(&include_path, source_dir.as_deref(), include_paths)
        {
            let canonical = match resolved.canonicalize() {
                Ok(c) => c,
                Err(_) => resolved.clone(),
            };
            if resolved_set.contains(&canonical) {
                continue;
            }
            resolved_set.insert(canonical);

            let header_path = resolved.to_string_lossy().to_string();
            if let Ok((htree, hsource)) = parser.parse_file(&header_path) {
                let root = htree.root_node();
                collect_function_names(&root, &hsource, &mut context.known_functions);
                collect_header_declarations(
                    &root,
                    &hsource,
                    &mut context.header_declared_functions,
                );
                // Collect macro constants and aliases from resolved headers
                let header_macros = const_eval::collect_macro_constants(&root, &hsource);
                context.macro_constants.extend(header_macros.clone());

                let header_aliases = const_eval::collect_macro_aliases(&root, &hsource);
                let header_taint_aliases: Vec<String> = header_aliases
                    .iter()
                    .filter(|(_, target)| {
                        function_summary::ENV03_TAINT_SOURCE_FUNCTIONS.contains(&target.as_str())
                    })
                    .map(|(alias, _)| alias.clone())
                    .collect();

                let header_string_macros =
                    const_eval::collect_string_literal_macros(&root, &hsource);
                let file_summaries = function_summary::compute_summaries(
                    &root,
                    &hsource,
                    &header_macros,
                    needs_vra,
                    &header_taint_aliases,
                    &header_string_macros,
                );
                for (name, summary) in file_summaries {
                    context.function_summaries.insert(name, summary);
                }
                context.macro_aliases.extend(header_aliases);

                // Collect struct field types from resolved headers
                collect_struct_definitions(&root, &hsource, &mut context.struct_field_types);

                // Enqueue transitive includes from this header
                let header_dir = resolved.parent().map(|p| p.to_path_buf());
                for inc in extract_include_directives(&root, &hsource) {
                    queue.push((inc, header_dir.clone()));
                }
            }
        }
    }

    if let Some(reporter) = progress {
        reporter.report_include_resolve_complete(resolved_set.len());
    }

    Ok(())
}

/// Extract `#include` directive paths from an AST.
///
/// Walks `preproc_include` nodes and extracts the path string, stripping
/// both `"..."` and `<...>` delimiters. Recurses into `preproc_*` nodes
/// to handle conditional includes.
fn extract_include_directives(node: &Node, source: &str) -> Vec<String> {
    let mut directives = Vec::new();
    extract_includes_recursive(node, source, &mut directives);
    directives
}

fn extract_includes_recursive(node: &Node, source: &str, directives: &mut Vec<String>) {
    match node.kind() {
        "preproc_include" => {
            // The path child contains the include path (e.g. "foo.h" or <foo.h>)
            if let Some(path_node) = node.child_by_field_name("path") {
                if let Ok(text) = path_node.utf8_text(source.as_bytes()) {
                    let text = text.trim();
                    // Strip delimiters: "foo.h" -> foo.h, <foo.h> -> foo.h
                    let path = if (text.starts_with('"') && text.ends_with('"'))
                        || (text.starts_with('<') && text.ends_with('>'))
                    {
                        &text[1..text.len() - 1]
                    } else {
                        text
                    };
                    if !path.is_empty() {
                        directives.push(path.to_string());
                    }
                }
            }
        }
        kind if kind.starts_with("preproc_") => {
            // Recurse into conditional compilation blocks
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    extract_includes_recursive(&child, source, directives);
                }
            }
        }
        _ => {}
    }

    // For non-preproc nodes, walk children (translation_unit, etc.)
    if !node.kind().starts_with("preproc_") {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                extract_includes_recursive(&child, source, directives);
            }
        }
    }
}

/// Resolve an include path against search directories.
///
/// Search order: (1) source file's directory (if available), (2) each `-I`
/// path in order. Returns the first match where the candidate is a file.
fn resolve_header(
    include_path: &str,
    source_dir: Option<&Path>,
    include_search_paths: &[String],
) -> Option<PathBuf> {
    // First: try relative to the source file's directory
    if let Some(dir) = source_dir {
        let candidate = dir.join(include_path);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    // Then: try each -I path in order
    for search_dir in include_search_paths {
        let candidate = Path::new(search_dir).join(include_path);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_c(code: &str) -> (tree_sitter::Tree, String) {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        (tree, code.to_string())
    }

    // -- callsite buffer-size collection / aggregation --

    #[test]
    fn test_collect_buf_args_resolves_alloc_and_alias() {
        // `data` aliases an ALLOCA(50) buffer; the call to `sink` should record
        // a 50-element buffer at param 0.
        let code = r#"
            void caller(void) {
                char * data;
                char * buf = (char *)ALLOCA(50 * sizeof(char));
                data = buf;
                sink(data);
            }
        "#;
        let (tree, source) = parse_c(code);
        let mut out = HashMap::new();
        collect_callsite_buf_args_from_tree(&tree.root_node(), &source, &mut out);
        assert_eq!(out.get("sink"), Some(&vec![vec![Some(50usize)]]));
    }

    #[test]
    fn test_aggregate_buf_args_takes_min_and_skips_unresolved() {
        let mut sites: HashMap<String, Vec<Vec<Option<usize>>>> = HashMap::new();
        // Two callers of `good` pass 100 and 200 → min 100 recorded.
        sites.insert("good".into(), vec![vec![Some(100)], vec![Some(200)]]);
        // `mixed` has one resolved and one unresolved caller → not recorded.
        sites.insert("mixed".into(), vec![vec![Some(100)], vec![None]]);
        let mut summaries: HashMap<String, FunctionSummary> = HashMap::new();
        summaries.insert("good".into(), FunctionSummary::default());
        summaries.insert("mixed".into(), FunctionSummary::default());
        aggregate_callsite_buf_args(&sites, &mut summaries, &HashSet::new());
        assert_eq!(
            summaries["good"].callsite_param_buffer_size.get(&0),
            Some(&100usize)
        );
        assert!(summaries["mixed"].callsite_param_buffer_size.is_empty());
    }

    #[test]
    fn test_aggregate_buf_args_skips_header_declared() {
        let mut sites: HashMap<String, Vec<Vec<Option<usize>>>> = HashMap::new();
        sites.insert("pub_api".into(), vec![vec![Some(100)]]);
        let mut summaries: HashMap<String, FunctionSummary> = HashMap::new();
        summaries.insert("pub_api".into(), FunctionSummary::default());
        let mut headers = HashSet::new();
        headers.insert("pub_api".to_string());
        aggregate_callsite_buf_args(&sites, &mut summaries, &headers);
        // External callers are unknowable → no bound recorded.
        assert!(summaries["pub_api"].callsite_param_buffer_size.is_empty());
    }

    // -- collect_function_names --

    #[test]
    fn test_collect_function_names_definitions() {
        let code = "void foo(void) {} int bar(int x) { return x; }";
        let (tree, source) = parse_c(code);
        let mut names = HashSet::new();
        collect_function_names(&tree.root_node(), &source, &mut names);
        assert!(names.contains("foo"));
        assert!(names.contains("bar"));
    }

    #[test]
    fn test_collect_function_names_declarations() {
        let code = "void foo(void); int bar(int x);";
        let (tree, source) = parse_c(code);
        let mut names = HashSet::new();
        collect_function_names(&tree.root_node(), &source, &mut names);
        assert!(names.contains("foo"));
        assert!(names.contains("bar"));
    }

    #[test]
    fn test_collect_function_names_pointer_return() {
        let code = "char *strdup(const char *s); int *get_ptr(void) { return 0; }";
        let (tree, source) = parse_c(code);
        let mut names = HashSet::new();
        collect_function_names(&tree.root_node(), &source, &mut names);
        assert!(names.contains("strdup"));
        assert!(names.contains("get_ptr"));
    }

    #[test]
    fn test_collect_function_names_inside_ifdef() {
        let code = "#ifdef FEATURE\nvoid guarded(void) {}\n#endif\n";
        let (tree, source) = parse_c(code);
        let mut names = HashSet::new();
        collect_function_names(&tree.root_node(), &source, &mut names);
        assert!(names.contains("guarded"));
    }

    #[test]
    fn test_collect_function_names_macro() {
        let code = "#define MY_FUNC(x) ((x) + 1)\n";
        let (tree, source) = parse_c(code);
        let mut names = HashSet::new();
        collect_function_names(&tree.root_node(), &source, &mut names);
        assert!(names.contains("MY_FUNC"));
    }

    // -- collect_header_declarations --

    #[test]
    fn test_collect_header_declarations_skips_static() {
        let code = "void public_func(int x);\nstatic void internal(void);";
        let (tree, source) = parse_c(code);
        let mut names = HashSet::new();
        collect_header_declarations(&tree.root_node(), &source, &mut names);
        assert!(names.contains("public_func"));
        assert!(!names.contains("internal"));
    }

    // -- collect_call_graph --

    #[test]
    fn test_collect_call_graph() {
        let code = "void a(void) { b(); c(); } void b(void) { c(); }";
        let (tree, source) = parse_c(code);
        let mut graph = HashMap::new();
        collect_call_graph(&tree.root_node(), &source, &mut graph);
        assert!(graph.get("a").unwrap().contains("b"));
        assert!(graph.get("a").unwrap().contains("c"));
        assert!(graph.get("b").unwrap().contains("c"));
    }

    #[test]
    fn test_collect_call_graph_resolves_fn_ptr_alias() {
        // Juliet variant 65a pattern: function pointer assigned to a sink
        // function, then invoked via the pointer. The call graph should
        // record the underlying function as a callee of `caller`.
        let code = "void target(char *d) {}\n\
                    void caller(void) {\n\
                        void (*fp)(char *) = target;\n\
                        char *data = 0;\n\
                        fp(data);\n\
                    }";
        let (tree, source) = parse_c(code);
        let mut graph = HashMap::new();
        collect_call_graph(&tree.root_node(), &source, &mut graph);
        let callees = graph.get("caller").expect("caller present");
        assert!(
            callees.contains("target"),
            "expected 'target' in callees, got {callees:?}"
        );
    }

    #[test]
    fn test_collect_call_graph_resolves_fn_ptr_address_of() {
        // Initializer uses the address-of form `&target`, exercising the
        // unary-argument unwrap in `rhs_target_function_name`.
        let code = "void target(int x) {}\n\
                    void caller(void) {\n\
                        int (*fp)(int) = &target;\n\
                        fp(1);\n\
                    }";
        let (tree, source) = parse_c(code);
        let mut graph = HashMap::new();
        collect_call_graph(&tree.root_node(), &source, &mut graph);
        let callees = graph.get("caller").expect("caller present");
        assert!(
            callees.contains("target"),
            "expected 'target' in callees, got {callees:?}"
        );
    }

    #[test]
    fn test_collect_call_graph_ifdef_spanning_brace_does_not_leak_swallowed_sibling_calls() {
        // Regression for the sqlite3Init/sqlite3InitOne false MSC04-C
        // indirect-recursion cycle (task 267/296), reproduced with the real
        // sqlite3/src/prepare.c source (trimmed to the two functions
        // involved): a brace that opens under `#ifndef
        // SQLITE_OMIT_AUTHORIZATION` and closes under a second, identical
        // guard a few lines later can't be reconciled by tree-sitter-c
        // without a real preprocessor. It emits a local error and
        // sqlite3InitOne's function_definition never closes normally,
        // nesting sqlite3Init as a descendant. Without the has_error()
        // guard, sqlite3InitOne's callee set wrongly absorbed sqlite3Init's
        // calls too -- including a call back to sqlite3InitOne itself,
        // producing a false self-recursion edge that doesn't exist in the
        // source.
        let code = r#"int sqlite3InitOne(sqlite3 *db, int iDb, char **pzErrMsg, u32 mFlags){
  int rc;
  int i;
#ifndef SQLITE_OMIT_DEPRECATED
  int size;
#endif
  Db *pDb;
  char const *azArg[6];
  int meta[5];
  InitData initData;
  const char *zSchemaTabName;
  int openedTransaction = 0;
  int mask = ((db->mDbFlags & DBFLAG_EncodingFixed) | ~DBFLAG_EncodingFixed);

  assert( (db->mDbFlags & DBFLAG_SchemaKnownOk)==0 );
  assert( iDb>=0 && iDb<db->nDb );
  assert( db->aDb[iDb].pSchema );
  assert( sqlite3_mutex_held(db->mutex) );
  assert( iDb==1 || sqlite3BtreeHoldsMutex(db->aDb[iDb].pBt) );

  db->init.busy = 1;

  /* Construct the in-memory representation schema tables (sqlite_schema or
  ** sqlite_temp_schema) by invoking the parser directly.  The appropriate
  ** table name will be inserted automatically by the parser so we can just
  ** use the abbreviation "x" here.  The parser will also automatically tag
  ** the schema table as read-only. */
  azArg[0] = "table";
  azArg[1] = zSchemaTabName = SCHEMA_TABLE(iDb);
  azArg[2] = azArg[1];
  azArg[3] = "1";
  azArg[4] = "CREATE TABLE x(type text,name text,tbl_name text,"
                            "rootpage int,sql text)";
  azArg[5] = 0;
  initData.db = db;
  initData.iDb = iDb;
  initData.rc = SQLITE_OK;
  initData.pzErrMsg = pzErrMsg;
  initData.mInitFlags = mFlags;
  initData.nInitRow = 0;
  initData.mxPage = 0;
  sqlite3InitCallback(&initData, 5, (char **)azArg, 0);
  db->mDbFlags &= mask;
  if( initData.rc ){
    rc = initData.rc;
    goto error_out;
  }

  /* Create a cursor to hold the database open
  */
  pDb = &db->aDb[iDb];
  if( pDb->pBt==0 ){
    assert( iDb==1 );
    DbSetProperty(db, 1, DB_SchemaLoaded);
    rc = SQLITE_OK;
    goto error_out;
  }

  /* If there is not already a read-only (or read-write) transaction opened
  ** on the b-tree database, open one now. If a transaction is opened, it 
  ** will be closed before this function returns.  */
  sqlite3BtreeEnter(pDb->pBt);
  if( sqlite3BtreeTxnState(pDb->pBt)==SQLITE_TXN_NONE ){
    rc = sqlite3BtreeBeginTrans(pDb->pBt, 0, 0);
    if( rc!=SQLITE_OK ){
      sqlite3SetString(pzErrMsg, db, sqlite3ErrStr(rc));
      goto initone_error_out;
    }
    openedTransaction = 1;
  }

  /* Get the database meta information.
  **
  ** Meta values are as follows:
  **    meta[0]   Schema cookie.  Changes with each schema change.
  **    meta[1]   File format of schema layer.
  **    meta[2]   Size of the page cache.
  **    meta[3]   Largest rootpage (auto/incr_vacuum mode)
  **    meta[4]   Db text encoding. 1:UTF-8 2:UTF-16LE 3:UTF-16BE
  **    meta[5]   User version
  **    meta[6]   Incremental vacuum mode
  **    meta[7]   unused
  **    meta[8]   unused
  **    meta[9]   unused
  **
  ** Note: The #defined SQLITE_UTF* symbols in sqliteInt.h correspond to
  ** the possible values of meta[4].
  */
  for(i=0; i<ArraySize(meta); i++){
    sqlite3BtreeGetMeta(pDb->pBt, i+1, (u32 *)&meta[i]);
  }
  if( (db->flags & SQLITE_ResetDatabase)!=0 ){
    memset(meta, 0, sizeof(meta));
  }
  pDb->pSchema->schema_cookie = meta[BTREE_SCHEMA_VERSION-1];

  /* If opening a non-empty database, check the text encoding. For the
  ** main database, set sqlite3.enc to the encoding of the main database.
  ** For an attached db, it is an error if the encoding is not the same
  ** as sqlite3.enc.
  */
  if( meta[BTREE_TEXT_ENCODING-1] ){  /* text encoding */
    if( iDb==0 && (db->mDbFlags & DBFLAG_EncodingFixed)==0 ){
      u8 encoding;
#ifndef SQLITE_OMIT_UTF16
      /* If opening the main database, set ENC(db). */
      encoding = (u8)meta[BTREE_TEXT_ENCODING-1] & 3;
      if( encoding==0 ) encoding = SQLITE_UTF8;
#else
      encoding = SQLITE_UTF8;
#endif
      sqlite3SetTextEncoding(db, encoding);
    }else{
      /* If opening an attached database, the encoding much match ENC(db) */
      if( (meta[BTREE_TEXT_ENCODING-1] & 3)!=ENC(db) ){
        sqlite3SetString(pzErrMsg, db, "attached databases must use the same"
            " text encoding as main database");
        rc = SQLITE_ERROR;
        goto initone_error_out;
      }
    }
  }
  pDb->pSchema->enc = ENC(db);

  if( pDb->pSchema->cache_size==0 ){
#ifndef SQLITE_OMIT_DEPRECATED
    size = sqlite3AbsInt32(meta[BTREE_DEFAULT_CACHE_SIZE-1]);
    if( size==0 ){ size = SQLITE_DEFAULT_CACHE_SIZE; }
    pDb->pSchema->cache_size = size;
#else
    pDb->pSchema->cache_size = SQLITE_DEFAULT_CACHE_SIZE;
#endif
    sqlite3BtreeSetCacheSize(pDb->pBt, pDb->pSchema->cache_size);
  }

  /*
  ** file_format==1    Version 3.0.0.
  ** file_format==2    Version 3.1.3.  // ALTER TABLE ADD COLUMN
  ** file_format==3    Version 3.1.4.  // ditto but with non-NULL defaults
  ** file_format==4    Version 3.3.0.  // DESC indices.  Boolean constants
  */
  pDb->pSchema->file_format = (u8)meta[BTREE_FILE_FORMAT-1];
  if( pDb->pSchema->file_format==0 ){
    pDb->pSchema->file_format = 1;
  }
  if( pDb->pSchema->file_format>SQLITE_MAX_FILE_FORMAT ){
    sqlite3SetString(pzErrMsg, db, "unsupported file format");
    rc = SQLITE_ERROR;
    goto initone_error_out;
  }

  /* Ticket #2804:  When we open a database in the newer file format,
  ** clear the legacy_file_format pragma flag so that a VACUUM will
  ** not downgrade the database and thus invalidate any descending
  ** indices that the user might have created.
  */
  if( iDb==0 && meta[BTREE_FILE_FORMAT-1]>=4 ){
    db->flags &= ~(u64)SQLITE_LegacyFileFmt;
  }

  /* Read the schema information out of the schema tables
  */
  assert( db->init.busy );
  initData.mxPage = sqlite3BtreeLastPage(pDb->pBt);
  {
    char *zSql;
    zSql = sqlite3MPrintf(db, 
        "SELECT*FROM\"%w\".%s ORDER BY rowid",
        db->aDb[iDb].zDbSName, zSchemaTabName);
#ifndef SQLITE_OMIT_AUTHORIZATION
    {
      sqlite3_xauth xAuth;
      xAuth = db->xAuth;
      db->xAuth = 0;
#endif
      rc = sqlite3_exec(db, zSql, sqlite3InitCallback, &initData, 0);
#ifndef SQLITE_OMIT_AUTHORIZATION
      db->xAuth = xAuth;
    }
#endif
    if( rc==SQLITE_OK ) rc = initData.rc;
    sqlite3DbFree(db, zSql);
#ifndef SQLITE_OMIT_ANALYZE
    if( rc==SQLITE_OK ){
      sqlite3AnalysisLoad(db, iDb);
    }
#endif
  }
  assert( pDb == &(db->aDb[iDb]) );
  if( db->mallocFailed ){
    rc = SQLITE_NOMEM_BKPT;
    sqlite3ResetAllSchemasOfConnection(db);
    pDb = &db->aDb[iDb];
  }else
  if( rc==SQLITE_OK || ((db->flags&SQLITE_NoSchemaError) && rc!=SQLITE_NOMEM)){
    /* Hack: If the SQLITE_NoSchemaError flag is set, then consider
    ** the schema loaded, even if errors (other than OOM) occurred. In
    ** this situation the current sqlite3_prepare() operation will fail,
    ** but the following one will attempt to compile the supplied statement
    ** against whatever subset of the schema was loaded before the error
    ** occurred.
    **
    ** The primary purpose of this is to allow access to the sqlite_schema
    ** table even when its contents have been corrupted.
    */
    DbSetProperty(db, iDb, DB_SchemaLoaded);
    rc = SQLITE_OK;
  }

  /* Jump here for an error that occurs after successfully allocating
  ** curMain and calling sqlite3BtreeEnter(). For an error that occurs
  ** before that point, jump to error_out.
  */
initone_error_out:
  if( openedTransaction ){
    sqlite3BtreeCommit(pDb->pBt);
  }
  sqlite3BtreeLeave(pDb->pBt);

error_out:
  if( rc ){
    if( rc==SQLITE_NOMEM || rc==SQLITE_IOERR_NOMEM ){
      sqlite3OomFault(db);
    }
    sqlite3ResetOneSchema(db, iDb);
  }
  db->init.busy = 0;
  return rc;
}

/*
** Initialize all database files - the main database file, the file
** used to store temporary tables, and any additional database files
** created using ATTACH statements.  Return a success code.  If an
** error occurs, write an error message into *pzErrMsg.
**
** After a database is initialized, the DB_SchemaLoaded bit is set
** bit is set in the flags field of the Db structure. 
*/
int sqlite3Init(sqlite3 *db, char **pzErrMsg){
  int i, rc;
  int commit_internal = !(db->mDbFlags&DBFLAG_SchemaChange);
  
  assert( sqlite3_mutex_held(db->mutex) );
  assert( sqlite3BtreeHoldsMutex(db->aDb[0].pBt) );
  assert( db->init.busy==0 );
  ENC(db) = SCHEMA_ENC(db);
  assert( db->nDb>0 );
  /* Do the main schema first */
  if( !DbHasProperty(db, 0, DB_SchemaLoaded) ){
    rc = sqlite3InitOne(db, 0, pzErrMsg, 0);
    if( rc ) return rc;
  }
  /* All other schemas after the main schema. The "temp" schema must be last */
  for(i=db->nDb-1; i>0; i--){
    assert( i==1 || sqlite3BtreeHoldsMutex(db->aDb[i].pBt) );
    if( !DbHasProperty(db, i, DB_SchemaLoaded) ){
      rc = sqlite3InitOne(db, i, pzErrMsg, 0);
      if( rc ) return rc;
    }
  }
  if( commit_internal ){
    sqlite3CommitInternalChanges(db);
  }
  return SQLITE_OK;
}

"#;
        let (tree, source) = parse_c(code);
        let mut graph = HashMap::new();
        collect_call_graph(&tree.root_node(), &source, &mut graph);

        // The real edge must still be found (via sqlite3Init's own,
        // correctly scoped span).
        assert!(
            graph.get("sqlite3Init").unwrap().contains("sqlite3InitOne"),
            "expected sqlite3Init -> sqlite3InitOne, got {:?}",
            graph.get("sqlite3Init")
        );
        // sqlite3InitOne must NOT be credited with calling itself -- that
        // edge only exists because the corrupted span swallowed sqlite3Init
        // (whose real body calls sqlite3InitOne) as a descendant.
        let init_one_callees = graph.get("sqlite3InitOne").cloned().unwrap_or_default();
        assert!(
            !init_one_callees.contains("sqlite3InitOne"),
            "false self-recursion edge leaked into sqlite3InitOne's callees: {init_one_callees:?}"
        );
        // Likewise sqlite3CommitInternalChanges is only ever called from
        // sqlite3Init's real body, never sqlite3InitOne's.
        assert!(
            !init_one_callees.contains("sqlite3CommitInternalChanges"),
            "sqlite3Init's callees leaked into sqlite3InitOne: {init_one_callees:?}"
        );
    }

    #[test]
    fn test_collect_call_graph_mis_parsed_if_does_not_lose_real_calls() {
        // Regression for a second false-negative discovered while validating
        // the has_error() fix above: sqlite3/src/vdbemem.c's valueFromExpr
        // has an unrelated, separate parse error that makes tree-sitter-c
        // mis-parse one of its `if` blocks as a nameless
        // function_definition-shaped node. That node is NOT a real swallowed
        // sibling (extract_function_name_from_declarator returns None for
        // it, so it never gets its own call-graph entry) -- it's debris from
        // error recovery, and the real call to valueFromFunction lives
        // textually inside it. Stopping at every nested function_definition
        // once has_error() is true (the naive version of the fix) silently
        // dropped that real call. The fix must only stop at *nameable*
        // nested nodes.
        let code = r#"static int valueFromExpr(
  sqlite3 *db,                    /* The database connection */
  const Expr *pExpr,              /* The expression to evaluate */
  u8 enc,                         /* Encoding to use */
  u8 affinity,                    /* Affinity to use */
  sqlite3_value **ppVal,          /* Write the new value here */
  struct ValueNewStat4Ctx *pCtx   /* Second argument for valueNew() */
){
  int op;
  char *zVal = 0;
  sqlite3_value *pVal = 0;
  int negInt = 1;
  const char *zNeg = "";
  int rc = SQLITE_OK;

  assert( pExpr!=0 );
  while( (op = pExpr->op)==TK_UPLUS || op==TK_SPAN ) pExpr = pExpr->pLeft;
  if( op==TK_REGISTER ) op = pExpr->op2;

  /* Compressed expressions only appear when parsing the DEFAULT clause
  ** on a table column definition, and hence only when pCtx==0.  This
  ** check ensures that an EP_TokenOnly expression is never passed down
  ** into valueFromFunction(). */
  assert( (pExpr->flags & EP_TokenOnly)==0 || pCtx==0 );

  if( op==TK_CAST ){
    u8 aff;
    assert( !ExprHasProperty(pExpr, EP_IntValue) );
    aff = sqlite3AffinityType(pExpr->u.zToken,0);
    rc = valueFromExpr(db, pExpr->pLeft, enc, aff, ppVal, pCtx);
    testcase( rc!=SQLITE_OK );
    if( *ppVal ){
#ifdef SQLITE_ENABLE_STAT4
      rc = ExpandBlob(*ppVal);
#else
      /* zero-blobs only come from functions, not literal values.  And
      ** functions are only processed under STAT4 */
      assert( (ppVal[0][0].flags & MEM_Zero)==0 );
#endif
      sqlite3VdbeMemCast(*ppVal, aff, enc);
      sqlite3ValueApplyAffinity(*ppVal, affinity, enc);
    }
    return rc;
  }

  /* Handle negative integers in a single step.  This is needed in the
  ** case when the value is -9223372036854775808. Except - do not do this
  ** for hexadecimal literals.  */
  if( op==TK_UMINUS ){
    Expr *pLeft = pExpr->pLeft;
    if( (pLeft->op==TK_INTEGER || pLeft->op==TK_FLOAT) ){
      if( ExprHasProperty(pLeft, EP_IntValue)
       || pLeft->u.zToken[0]!='0' || (pLeft->u.zToken[1] & ~0x20)!='X'
      ){
        pExpr = pLeft;
        op = pExpr->op;
        negInt = -1;
        zNeg = "-";
      }
    }
  }

  if( op==TK_STRING || op==TK_FLOAT || op==TK_INTEGER ){
    pVal = valueNew(db, pCtx);
    if( pVal==0 ) goto no_mem;
    if( ExprHasProperty(pExpr, EP_IntValue) ){
      sqlite3VdbeMemSetInt64(pVal, (i64)pExpr->u.iValue*negInt);
    }else{
      i64 iVal;
      if( op==TK_INTEGER && 0==sqlite3DecOrHexToI64(pExpr->u.zToken, &iVal) ){
        sqlite3VdbeMemSetInt64(pVal, iVal*negInt);
      }else{
        zVal = sqlite3MPrintf(db, "%s%s", zNeg, pExpr->u.zToken);
        if( zVal==0 ) goto no_mem;
        sqlite3ValueSetStr(pVal, -1, zVal, SQLITE_UTF8, SQLITE_DYNAMIC);
      }
    }
    if( affinity==SQLITE_AFF_BLOB ){
      if( op==TK_FLOAT ){
        assert( pVal && pVal->z && pVal->flags==(MEM_Str|MEM_Term) );
        sqlite3AtoF(pVal->z, &pVal->u.r);
        pVal->flags = MEM_Real;
      }else if( op==TK_INTEGER ){
        /* This case is required by -9223372036854775808 and other strings
        ** that look like integers but cannot be handled by the
        ** sqlite3DecOrHexToI64() call above.  */
        sqlite3ValueApplyAffinity(pVal, SQLITE_AFF_NUMERIC, SQLITE_UTF8);
      }
    }else{
      sqlite3ValueApplyAffinity(pVal, affinity, SQLITE_UTF8);
    }
    assert( (pVal->flags & MEM_IntReal)==0 );
    if( pVal->flags & (MEM_Int|MEM_IntReal|MEM_Real) ){
      testcase( pVal->flags & MEM_Int );
      testcase( pVal->flags & MEM_Real );
      pVal->flags &= ~MEM_Str;
    }
    if( enc!=SQLITE_UTF8 ){
      rc = sqlite3VdbeChangeEncoding(pVal, enc);
    }
  }else if( op==TK_UMINUS ) {
    /* This branch happens for multiple negative signs.  Ex: -(-5) */
    if( SQLITE_OK==valueFromExpr(db,pExpr->pLeft,enc,affinity,&pVal,pCtx) 
     && pVal!=0
    ){
      sqlite3VdbeMemNumerify(pVal);
      if( pVal->flags & MEM_Real ){
        pVal->u.r = -pVal->u.r;
      }else if( pVal->u.i==SMALLEST_INT64 ){
#ifndef SQLITE_OMIT_FLOATING_POINT
        pVal->u.r = -(double)SMALLEST_INT64;
#else
        pVal->u.r = LARGEST_INT64;
#endif
        MemSetTypeFlag(pVal, MEM_Real);
      }else{
        pVal->u.i = -pVal->u.i;
      }
      sqlite3ValueApplyAffinity(pVal, affinity, enc);
    }
  }else if( op==TK_NULL ){
    pVal = valueNew(db, pCtx);
    if( pVal==0 ) goto no_mem;
    sqlite3VdbeMemSetNull(pVal);
  }
#ifndef SQLITE_OMIT_BLOB_LITERAL
  else if( op==TK_BLOB ){
    int nVal;
    assert( !ExprHasProperty(pExpr, EP_IntValue) );
    assert( pExpr->u.zToken[0]=='x' || pExpr->u.zToken[0]=='X' );
    assert( pExpr->u.zToken[1]=='\'' );
    pVal = valueNew(db, pCtx);
    if( !pVal ) goto no_mem;
    zVal = &pExpr->u.zToken[2];
    nVal = sqlite3Strlen30(zVal)-1;
    assert( zVal[nVal]=='\'' );
    sqlite3VdbeMemSetStr(pVal, sqlite3HexToBlob(db, zVal, nVal), nVal/2,
                         0, SQLITE_DYNAMIC);
  }
#endif
#ifdef SQLITE_ENABLE_STAT4
  else if( op==TK_FUNCTION && pCtx!=0 ){
    rc = valueFromFunction(db, pExpr, enc, affinity, &pVal, pCtx);
  }
#endif
  else if( op==TK_TRUEFALSE ){
    assert( !ExprHasProperty(pExpr, EP_IntValue) );
    pVal = valueNew(db, pCtx);
    if( pVal ){
      pVal->flags = MEM_Int;
      pVal->u.i = pExpr->u.zToken[4]==0;
      sqlite3ValueApplyAffinity(pVal, affinity, enc);
    }
  }

  *ppVal = pVal;
  return rc;

no_mem:
#ifdef SQLITE_ENABLE_STAT4
  if( pCtx==0 || NEVER(pCtx->pParse->nErr==0) )
#endif
    sqlite3OomFault(db);
  sqlite3DbFree(db, zVal);
  assert( *ppVal==0 );
#ifdef SQLITE_ENABLE_STAT4
  if( pCtx==0 ) sqlite3ValueFree(pVal);
#else
  assert( pCtx==0 ); sqlite3ValueFree(pVal);
#endif
  return SQLITE_NOMEM_BKPT;
}

/*
"#;
        let (tree, source) = parse_c(code);
        let mut graph = HashMap::new();
        collect_call_graph(&tree.root_node(), &source, &mut graph);
        let callees = graph.get("valueFromExpr").cloned().unwrap_or_default();
        assert!(
            callees.contains("valueFromFunction"),
            "real call inside a mis-parsed if-block was dropped: {callees:?}"
        );
    }

    #[test]
    fn test_collect_call_graph_plain_pointer_not_aliased() {
        // A plain pointer assignment `void *p = some_var;` is not a function
        // pointer — make sure we don't pollute the call graph with `some_var`
        // as a callee just because p is later indirected somehow.
        let code = "void caller(void) {\n\
                        int x = 0;\n\
                        int *p = &x;\n\
                        *p = 1;\n\
                    }";
        let (tree, source) = parse_c(code);
        let mut graph = HashMap::new();
        collect_call_graph(&tree.root_node(), &source, &mut graph);
        let callees = graph.get("caller").cloned().unwrap_or_default();
        assert!(
            !callees.contains("x"),
            "plain pointer decl should not produce callee edge: {callees:?}"
        );
    }

    // -- collect_local_var_states --

    #[test]
    fn test_local_var_null() {
        let code = "void f(void) { int *p = NULL; }";
        let (tree, source) = parse_c(code);
        let func = tree.root_node().child(0).unwrap();
        let body = func.child_by_field_name("body").unwrap();
        let states = collect_local_var_states(&body, &source);
        assert_eq!(states.get("p"), Some(&NullState::DefinitelyNull));
    }

    #[test]
    fn test_local_var_string_literal() {
        let code = r#"void f(void) { char *s = "hello"; }"#;
        let (tree, source) = parse_c(code);
        let func = tree.root_node().child(0).unwrap();
        let body = func.child_by_field_name("body").unwrap();
        let states = collect_local_var_states(&body, &source);
        assert_eq!(states.get("s"), Some(&NullState::NotNull));
    }

    #[test]
    fn test_local_var_malloc() {
        let code = "void f(void) { void *p = malloc(10); }";
        let (tree, source) = parse_c(code);
        let func = tree.root_node().child(0).unwrap();
        let body = func.child_by_field_name("body").unwrap();
        let states = collect_local_var_states(&body, &source);
        assert_eq!(states.get("p"), Some(&NullState::PossiblyNull));
    }

    #[test]
    fn test_local_var_stack_array_not_null() {
        // Stack arrays are always non-null
        let code = "void f(void) { char buf[64]; }";
        let (tree, source) = parse_c(code);
        let func = tree.root_node().child(0).unwrap();
        let body = func.child_by_field_name("body").unwrap();
        let states = collect_local_var_states(&body, &source);
        assert_eq!(states.get("buf"), Some(&NullState::NotNull));
    }

    // -- collect_early_return_null_guards --

    #[test]
    fn test_early_return_null_guard() {
        let code = "void f(int *p) { if (p == NULL) return; *p = 1; }";
        let (tree, source) = parse_c(code);
        let func = tree.root_node().child(0).unwrap();
        let body = func.child_by_field_name("body").unwrap();
        let mut states = HashMap::new();
        collect_early_return_null_guards(&body, &source, &mut states);
        assert_eq!(states.get("p"), Some(&NullState::NotNull));
    }

    #[test]
    fn test_early_return_bang_guard() {
        let code = "void f(int *p) { if (!p) return; *p = 1; }";
        let (tree, source) = parse_c(code);
        let func = tree.root_node().child(0).unwrap();
        let body = func.child_by_field_name("body").unwrap();
        let mut states = HashMap::new();
        collect_early_return_null_guards(&body, &source, &mut states);
        assert_eq!(states.get("p"), Some(&NullState::NotNull));
    }

    // -- is_simple_identifier --

    #[test]
    fn test_is_simple_identifier() {
        assert!(is_simple_identifier("foo"));
        assert!(is_simple_identifier("_bar"));
        assert!(is_simple_identifier("baz123"));
        assert!(!is_simple_identifier(""));
        assert!(!is_simple_identifier("123abc"));
        assert!(!is_simple_identifier("a b"));
        assert!(!is_simple_identifier("a+b"));
    }

    // -- collect_struct_definitions --

    #[test]
    fn test_struct_named() {
        let code = "struct Point { int x; int y; };";
        let (tree, source) = parse_c(code);
        let mut fields = HashMap::new();
        collect_struct_definitions(&tree.root_node(), &source, &mut fields);
        let point = fields.get("Point").expect("Point not found");
        assert_eq!(point.get("x"), Some(&"int".to_string()));
        assert_eq!(point.get("y"), Some(&"int".to_string()));
    }

    #[test]
    fn test_struct_typedef() {
        let code = "typedef struct { char *name; int age; } Person;";
        let (tree, source) = parse_c(code);
        let mut fields = HashMap::new();
        collect_struct_definitions(&tree.root_node(), &source, &mut fields);
        let person = fields.get("Person").expect("Person not found");
        assert!(person.contains_key("name"));
        assert!(person.contains_key("age"));
    }

    // -- extract_include_directives --

    #[test]
    fn test_extract_includes() {
        let code = "#include <stdio.h>\n#include \"myheader.h\"\n";
        let (tree, source) = parse_c(code);
        let dirs = extract_include_directives(&tree.root_node(), &source);
        assert!(dirs.contains(&"stdio.h".to_string()));
        assert!(dirs.contains(&"myheader.h".to_string()));
    }

    #[test]
    fn test_extract_includes_conditional() {
        let code = "#ifdef HAVE_FOO\n#include \"foo.h\"\n#endif\n";
        let (tree, source) = parse_c(code);
        let dirs = extract_include_directives(&tree.root_node(), &source);
        assert!(dirs.contains(&"foo.h".to_string()));
    }

    // -- resolve_header --

    #[test]
    fn test_resolve_header_source_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let header = dir.path().join("test.h");
        std::fs::File::create(&header).unwrap();
        let result = resolve_header("test.h", Some(dir.path()), &[]);
        assert!(result.is_some());
    }

    #[test]
    fn test_resolve_header_include_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let header = dir.path().join("sys.h");
        std::fs::File::create(&header).unwrap();
        let search = vec![dir.path().to_string_lossy().to_string()];
        let result = resolve_header("sys.h", None, &search);
        assert!(result.is_some());
    }

    #[test]
    fn test_resolve_header_not_found() {
        assert!(resolve_header("nonexistent.h", None, &[]).is_none());
    }

    // -- aggregate_callsite_null_states --

    #[test]
    fn test_aggregate_all_not_null() {
        let mut summaries = HashMap::new();
        summaries.insert(
            "sink".to_string(),
            FunctionSummary {
                dereferences_params: vec![0].into_iter().collect(),
                ..Default::default()
            },
        );
        let callsite_args = HashMap::from([(
            "sink".to_string(),
            vec![vec![NullState::NotNull], vec![NullState::NotNull]],
        )]);
        aggregate_callsite_null_states(&callsite_args, &mut summaries, &HashSet::new());
        assert_eq!(
            summaries
                .get("sink")
                .unwrap()
                .callsite_param_null_states
                .get(&0),
            Some(&NullState::NotNull)
        );
    }

    #[test]
    fn test_aggregate_any_null_produces_possibly_null() {
        let mut summaries = HashMap::new();
        summaries.insert(
            "sink".to_string(),
            FunctionSummary {
                dereferences_params: vec![0].into_iter().collect(),
                ..Default::default()
            },
        );
        let callsite_args = HashMap::from([(
            "sink".to_string(),
            vec![vec![NullState::NotNull], vec![NullState::DefinitelyNull]],
        )]);
        aggregate_callsite_null_states(&callsite_args, &mut summaries, &HashSet::new());
        assert_eq!(
            summaries
                .get("sink")
                .unwrap()
                .callsite_param_null_states
                .get(&0),
            Some(&NullState::PossiblyNull)
        );
    }

    // -- collect_callsite_args_from_tree --

    #[test]
    fn test_callsite_args_null() {
        let code = "void caller(void) { sink(NULL); }";
        let (tree, source) = parse_c(code);
        let mut args = HashMap::new();
        let mut field_args = HashMap::new();
        let mut pointee_args = HashMap::new();
        collect_callsite_args_from_tree(
            &tree.root_node(),
            &source,
            &mut args,
            &mut field_args,
            &mut pointee_args,
        );
        assert_eq!(args.get("sink").unwrap()[0][0], NullState::DefinitelyNull);
    }

    #[test]
    fn test_callsite_args_local_var() {
        let code = r#"void caller(void) { char *s = "hi"; sink(s); }"#;
        let (tree, source) = parse_c(code);
        let mut args = HashMap::new();
        let mut field_args = HashMap::new();
        let mut pointee_args = HashMap::new();
        collect_callsite_args_from_tree(
            &tree.root_node(),
            &source,
            &mut args,
            &mut field_args,
            &mut pointee_args,
        );
        assert_eq!(args.get("sink").unwrap()[0][0], NullState::NotNull);
    }

    // -- prescan_directories integration --

    #[test]
    fn test_prescan_directories_basic() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.c"), "void func_a(void) { func_b(); }").unwrap();
        std::fs::write(dir.path().join("b.c"), "void func_b(void) {}").unwrap();
        let dirs = vec![dir.path().to_string_lossy().to_string()];
        let ctx = prescan_directories(&dirs, None, false).unwrap();
        assert!(ctx.known_functions.contains("func_a"));
        assert!(ctx.known_functions.contains("func_b"));
        assert!(ctx.call_graph.get("func_a").unwrap().contains("func_b"));
    }

    #[test]
    fn test_prescan_directories_with_header() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("api.h"), "int public_api(int x);").unwrap();
        std::fs::write(
            dir.path().join("impl.c"),
            "int public_api(int x) { return x + 1; }",
        )
        .unwrap();
        let dirs = vec![dir.path().to_string_lossy().to_string()];
        let ctx = prescan_directories(&dirs, None, false).unwrap();
        assert!(ctx.known_functions.contains("public_api"));
        assert!(ctx.header_declared_functions.contains("public_api"));
    }

    #[test]
    fn test_prescan_directories_struct() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("types.c"),
            "struct Config { int timeout; char *host; };",
        )
        .unwrap();
        let dirs = vec![dir.path().to_string_lossy().to_string()];
        let ctx = prescan_directories(&dirs, None, false).unwrap();
        assert!(ctx
            .struct_field_types
            .get("Config")
            .unwrap()
            .contains_key("timeout"));
    }

    #[test]
    fn test_global_writers_non_static_extern_linkage() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("a.c"),
            "char *g_clean;\nstatic void write_clean(void) {\n    static char buf[64] = \"ls \";\n    g_clean = buf;\n}\n",
        ).unwrap();
        std::fs::write(
            dir.path().join("b.c"),
            "extern char *g_clean;\nvoid sink(void) { char *d = g_clean; system(d); }\n",
        )
        .unwrap();
        let dirs = vec![dir.path().to_string_lossy().to_string()];
        let ctx = prescan_directories(&dirs, None, false).unwrap();
        assert!(
            ctx.global_writers.contains_key("g_clean"),
            "g_clean should be tracked as a file-scope global: {:?}",
            ctx.global_writers.keys().collect::<Vec<_>>()
        );
        let writers = ctx.global_writers.get("g_clean").unwrap();
        assert!(
            writers.contains("write_clean"),
            "write_clean should be a writer of g_clean: {:?}",
            writers
        );
    }
}
