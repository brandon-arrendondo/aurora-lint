use super::super::{CertRule, RuleViolation};
use crate::analyze::argument_objects::{self, ObjectFrame};
use crate::analyze::context::ProjectContext;
use crate::analyze::prescan;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Arr36C {
    /// `struct_name -> field_name -> type_text` from the prescan, which is
    /// how a member's type is known when its struct is declared in another
    /// file. Empty without `-d`, so it is merged with the scanned file's own
    /// declarations rather than relied on (see `collect_pointer_members`).
    struct_field_types: RefCell<HashMap<String, HashMap<String, String>>>,
    /// `callee name -> argument-position pairs some call site ANYWHERE in the
    /// pre-scanned project proves denote two different objects`, from the
    /// prescan. Empty without `-d`, which is what the file-local
    /// `CallSiteBases` pass still covers (task 936).
    project_call_sites: RefCell<HashMap<String, HashSet<(usize, usize)>>>,
    /// `typedef struct Tag Alias;` from the prescan, `Alias -> Tag`. Without
    /// it a member reached through the alias does not resolve and falls back
    /// to naming storage (task 963).
    struct_typedef_aliases: RefCell<HashMap<String, String>>,
}

impl Arr36C {
    pub fn new() -> Self {
        Self {
            struct_field_types: RefCell::new(HashMap::new()),
            project_call_sites: RefCell::new(HashMap::new()),
            struct_typedef_aliases: RefCell::new(HashMap::new()),
        }
    }
}

impl CertRule for Arr36C {
    fn rule_id(&self) -> &'static str {
        "ARR36-C"
    }

    fn description(&self) -> &'static str {
        "Do not subtract or compare two pointers that do not refer to the same array"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "ARR36-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.struct_field_types.borrow_mut() = context.struct_field_types.clone();
        *self.struct_typedef_aliases.borrow_mut() = context.struct_typedef_aliases.clone();
        *self.project_call_sites.borrow_mut() = context
            .function_summaries
            .iter()
            .filter(|(_, summary)| !summary.distinct_object_param_pairs.is_empty())
            .map(|(name, summary)| (name.clone(), summary.distinct_object_param_pairs.clone()))
            .collect();
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Per-function analysis: create a fresh PointerAnalyzer for each function
        // to avoid cross-function variable name collisions.
        self.visit_functions(node, source, &mut violations);

        violations
    }
}

impl Arr36C {
    /// Walk the AST to find function_definition nodes, then analyze each independently.
    /// File-scope declarations (globals) are collected first and shared across all functions.
    fn visit_functions(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // First pass: collect file-scope declarations (global arrays, static vars)
        let mut file_scope = PointerAnalyzer::new();
        file_scope.collect_file_scope(node, source);

        // Second pass: per-function analysis with file-scope as base
        let project_fields = self.struct_field_types.borrow();
        let project_aliases = self.struct_typedef_aliases.borrow();
        let field_types = merge_file_struct_fields(&project_fields, &project_aliases, node, source);
        let funcs = query::find_descendants_of_kind(*node, "function_definition");
        let analyzers: Vec<PointerAnalyzer> = funcs
            .iter()
            .map(|func| {
                let mut analyzer = PointerAnalyzer::from(&file_scope);
                analyzer.collect_declarations(func, source);
                analyzer.collect_pointer_members(func, source, &field_types);
                analyzer
            })
            .collect();

        // Callers before callees: two pointer PARAMETERS are reported as
        // different arrays only when a call site in this file proves they are,
        // so every call site has to be read first (see `CallSiteBases`).
        let mut call_sites = CallSiteBases::default();
        for (func, analyzer) in funcs.iter().zip(&analyzers) {
            call_sites.collect_from(func, source, analyzer);
        }

        let project_call_sites = self.project_call_sites.borrow();
        for (func, analyzer) in funcs.iter().zip(&analyzers) {
            let frame = FrameContext {
                function_name: function_name_of(func, source),
                param_indices: parameter_indices(func, source),
                objects: &analyzer.objects,
                call_sites: &call_sites,
                project_call_sites: &project_call_sites,
            };
            self.check_node(func, source, analyzer, &frame, violations);
        }
    }

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        analyzer: &PointerAnalyzer,
        frame: &FrameContext,
        violations: &mut Vec<RuleViolation>,
    ) {
        for binary_expr in query::find_descendants_of_kind(*node, "binary_expression") {
            self.check_binary_expression(&binary_expr, source, analyzer, frame, violations);
        }
    }

    fn check_binary_expression(
        &self,
        node: &Node,
        source: &str,
        analyzer: &PointerAnalyzer,
        frame: &FrameContext,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(operator) = get_operator(node, source) {
            match operator.as_str() {
                "-" => {
                    self.check_pointer_subtraction(node, source, analyzer, frame, violations);
                }
                "<" | "<=" | ">" | ">=" => {
                    self.check_pointer_comparison(node, source, analyzer, frame, violations);
                }
                _ => {}
            }
        }
    }

    fn check_pointer_subtraction(
        &self,
        node: &Node,
        source: &str,
        analyzer: &PointerAnalyzer,
        frame: &FrameContext,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let left_info = analyzer.get_pointer_info(&left, source);
            let right_info = analyzer.get_pointer_info(&right, source);

            if let (Some(left_array), Some(right_array)) = (left_info, right_info) {
                if left_array != right_array && frame.reportable(&left_array, &right_array) {
                    let start_point = node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Pointer subtraction between pointers from different arrays: '{}' and '{}'",
                            left_array, right_array
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Ensure both pointers refer to the same array before subtraction".to_string()),
                        ..Default::default()
                    });
                }
            }
        }
    }

    fn check_pointer_comparison(
        &self,
        node: &Node,
        source: &str,
        analyzer: &PointerAnalyzer,
        frame: &FrameContext,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let left_info = analyzer.get_pointer_info(&left, source);
            let right_info = analyzer.get_pointer_info(&right, source);

            if let (Some(left_array), Some(right_array)) = (left_info, right_info) {
                if left_array != right_array && frame.reportable(&left_array, &right_array) {
                    let start_point = node.start_position();
                    let op = get_operator(node, source).unwrap_or("?".to_string());
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Pointer comparison '{}' between pointers from different arrays: '{}' and '{}'",
                            op, left_array, right_array
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Ensure both pointers refer to the same array before comparison".to_string()),
                        ..Default::default()
                    });
                }
            }
        }
    }
}

/// Where a base came from, as far as the frame that produced it can tell.
enum BaseOrigin {
    /// The base names storage: a declared array, an allocation, a literal, or
    /// an array-typed struct member.
    Storage,
    /// A pointer parameter of this function, at this position in its list.
    OwnParam(usize),
    /// A pointer-typed struct member.
    PointerMember,
    /// A pointer variable this frame declared but never learned a target for
    /// -- a bare `const u8 *next;`, or one assigned from a call the frame
    /// cannot see into. Its NAME is the base only because there was nothing
    /// better to record, not because it denotes storage.
    UntrackedPointer,
}

/// What one function's frame knows about the bases it produced, used to
/// decide whether a mismatched pair is a report this frame can make at all.
struct FrameContext<'a> {
    /// This function's name, when its declarator gives one. Call sites are
    /// matched to it by name, which is exact within one translation unit.
    function_name: Option<String>,
    /// Parameter name -> position in the parameter list, for every parameter
    /// of THIS function, pointer or not: an argument's position has to line
    /// up with the whole list.
    param_indices: HashMap<String, usize>,
    /// What this function's frame knows about which names denote storage,
    /// which merely hold a pointer, and which field paths are pointer-typed.
    objects: &'a ObjectFrame,
    call_sites: &'a CallSiteBases,
    /// The same predicate over every pre-scanned translation unit, so a
    /// callee whose callers all live elsewhere is still decided (task 936).
    project_call_sites: &'a HashMap<String, HashSet<(usize, usize)>>,
}

impl FrameContext<'_> {
    /// Whether a mismatched base pair is a violation this frame can claim.
    ///
    /// Two bases differ implies two arrays only when each base NAMES an
    /// object. Two kinds of base do not:
    ///
    /// A pointer parameter's base is synthetic (`param:name`), so two
    /// distinct parameters ALWAYS compare unequal -- which made every
    /// `(u8 **pos, u8 *end)` bounds check a violation even though the caller
    /// derives both from one buffer. Nothing inside the function settles it;
    /// the fact lives in the caller. So the default is inverted here: two
    /// parameters are taken to share an object unless a call site passes two
    /// provably distinct objects -- in this file, or anywhere the prescan
    /// reached (tasks 753 and 936).
    ///
    /// A pointer-typed struct member is the same thing one level over
    /// (task 935): `pOut->z` and `pC->aRow` are two different paths, and what
    /// they point AT is exactly as unknowable here as a parameter's target.
    /// An ARRAY-typed member is not -- `u.int_array` really is its own
    /// object, which is what ARR36-C-EX1 turns on -- so the two are told
    /// apart by the member's declared type, not by the shape of the path.
    ///
    /// An untracked pointer variable is the third instance of the same shape
    /// (task 962). `extract_array_base` returns the RAW NAME for an
    /// identifier it has no base for, so `end = next` over a bare
    /// `const u8 *next;` records `next` as a base and it then compares as
    /// though it named storage -- the one case the analyzer explicitly knows
    /// nothing about is the one whose name is taken at face value. A name
    /// declared a pointer and never declared as an array is exactly "a
    /// pointer whose target this frame never learned"; a declared array, a
    /// typedef array, an extern the frame never saw, and the address of a
    /// non-pointer scalar are all still storage, so ARR36-C-EX1 and every
    /// fail fixture are untouched.
    ///
    /// A pair with storage on either side is decided as before: a local array
    /// against a parameter is still settled inside the frame that declares
    /// it.
    fn reportable(&self, left: &str, right: &str) -> bool {
        match (self.origin(left), self.origin(right)) {
            // Two parameters: only a call site in this file settles it.
            (BaseOrigin::OwnParam(left), BaseOrigin::OwnParam(right)) => {
                match &self.function_name {
                    Some(name) => {
                        proves_distinct(&self.call_sites.per_callee, name, left, right)
                            || proves_distinct(self.project_call_sites, name, left, right)
                    }
                    None => false,
                }
            }
            // Neither side names an object, so nothing here says they are two.
            (
                BaseOrigin::OwnParam(_) | BaseOrigin::PointerMember | BaseOrigin::UntrackedPointer,
                BaseOrigin::OwnParam(_) | BaseOrigin::PointerMember | BaseOrigin::UntrackedPointer,
            ) => false,
            _ => true,
        }
    }

    fn origin(&self, base: &str) -> BaseOrigin {
        if let Some(index) = self.own_param_index(base) {
            return BaseOrigin::OwnParam(index);
        }
        if self.objects.pointer_members.contains(base) {
            return BaseOrigin::PointerMember;
        }
        // Declared a pointer and never declared as an array: the frame knows
        // the name can hold a pointer and knows nothing about its target.
        if self.objects.pointer_vars.contains(base) && !self.objects.array_objects.contains(base) {
            return BaseOrigin::UntrackedPointer;
        }
        BaseOrigin::Storage
    }

    /// Position of the parameter a `param:` base names, when it is a
    /// parameter of this function. `collect_declarations` also records
    /// parameters of nested declarators (a function-pointer parameter's own
    /// parameters), which are not in this list and yield `None`.
    fn own_param_index(&self, base: &str) -> Option<usize> {
        self.param_indices
            .get(base.strip_prefix("param:")?)
            .copied()
    }
}

/// Every direct call in this file, by callee name, recording the argument
/// positions at which one call site hands the callee two DIFFERENT named
/// storage objects.
///
/// This is the caller-side fact the parameter model needs, gathered in the
/// only frame `check()` has to itself. It is file-local by construction; the
/// prescan runs the same predicate over the whole project and delivers it as
/// `Arr36C::project_call_sites`, so a callee whose callers all live in other
/// translation units is covered there and only there (task 936).
#[derive(Default)]
struct CallSiteBases {
    per_callee: HashMap<String, HashSet<(usize, usize)>>,
}

impl CallSiteBases {
    /// Record every direct call in `func`, resolving each argument in the
    /// CALLER's own frame (`analyzer`).
    fn collect_from(&mut self, func: &Node, source: &str, analyzer: &PointerAnalyzer) {
        for call in query::find_descendants_of_kind(*func, "call_expression") {
            let (Some(callee), Some(args)) = (
                call.child_by_field_name("function"),
                call.child_by_field_name("arguments"),
            ) else {
                continue;
            };
            // Only a name resolves to a definition in this file; `obj->cb(...)`
            // is opaque.
            if callee.kind() != "identifier" {
                continue;
            }
            let pairs = argument_objects::distinct_object_pairs(
                &analyzer.objects,
                &argument_objects::argument_nodes(&args),
                source,
            );
            if pairs.is_empty() {
                continue;
            }
            self.per_callee
                .entry(ast_utils::get_node_text(&callee, source).to_string())
                .or_default()
                .extend(pairs);
        }
    }
}

/// True if some call site recorded in `per_callee` passes two named,
/// DIFFERENT storage objects at positions `left` and `right`. One such call
/// site is enough: if any caller passes two distinct arrays, the comparison
/// inside the callee is undefined whenever that caller's path runs.
fn proves_distinct(
    per_callee: &HashMap<String, HashSet<(usize, usize)>>,
    callee: &str,
    left: usize,
    right: usize,
) -> bool {
    let pair = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    per_callee
        .get(callee)
        .is_some_and(|pairs| pairs.contains(&pair))
}

/// Name of a function definition, from its (possibly pointer-wrapped)
/// declarator.
fn function_name_of(func: &Node, source: &str) -> Option<String> {
    let declarator = func.child_by_field_name("declarator")?;
    let name = ast_utils::get_identifier_from_declarator(&declarator, source);
    (!name.is_empty()).then_some(name)
}

/// This function's parameter names, mapped to their position in the parameter
/// list. Unnamed parameters (`void`, an abstract declarator) still consume a
/// position, so the count has to include them.
fn parameter_indices(func: &Node, source: &str) -> HashMap<String, usize> {
    let mut indices = HashMap::new();
    let Some(declarator) = func.child_by_field_name("declarator") else {
        return indices;
    };
    // Pre-order, so the function's own list comes before any list belonging to
    // a function-pointer parameter.
    let Some(list) = query::find_descendants_of_kind(declarator, "parameter_list")
        .first()
        .copied()
    else {
        return indices;
    };
    let params = (0..list.child_count())
        .filter_map(|i| list.child(i))
        .filter(|child| child.kind() == "parameter_declaration");
    for (position, param) in params.enumerate() {
        if let Some(param_declarator) = param.child_by_field_name("declarator") {
            let name = ast_utils::get_identifier_from_declarator(&param_declarator, source);
            if !name.is_empty() {
                indices.insert(name, position);
            }
        }
    }
    indices
}

struct PointerAnalyzer {
    // Maps variable names to their array base (for tracking which array they belong to)
    variable_arrays: HashMap<String, String>,
    // Which names in scope denote storage, which merely hold a pointer, and
    // which field paths are pointer-typed. `variable_arrays` answers "which
    // array is this in"; this answers the prior questions, and is shared with
    // the prescan so that a call site reads the same way in either frame
    // (`analyze::argument_objects`).
    objects: ObjectFrame,
}

impl PointerAnalyzer {
    fn new() -> Self {
        Self {
            variable_arrays: HashMap::new(),
            objects: ObjectFrame::new(),
        }
    }

    fn from(base: &PointerAnalyzer) -> Self {
        Self {
            variable_arrays: base.variable_arrays.clone(),
            objects: base.objects.clone(),
        }
    }

    /// Collect file-scope declarations (globals, statics at file level).
    /// Only processes direct children of translation_unit and preproc blocks.
    fn collect_file_scope(&mut self, node: &Node, source: &str) {
        match node.kind() {
            "translation_unit" | "preproc_ifdef" | "preproc_if" | "preproc_else"
            | "preproc_elif" => {
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "declaration" {
                            self.process_declaration(&child, source);
                        } else if child.kind().starts_with("preproc_") {
                            self.collect_file_scope(&child, source);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn collect_declarations(&mut self, node: &Node, source: &str) {
        let matches = query::find_descendants_of_kinds(
            *node,
            &[
                "declaration",
                "parameter_declaration",
                "expression_statement",
            ],
        );
        for n in matches {
            match n.kind() {
                "declaration" => {
                    self.process_declaration(&n, source);
                }
                "parameter_declaration" => {
                    self.process_parameter(&n, source);
                }
                "expression_statement" => {
                    self.process_assignment(&n, source);
                }
                _ => {}
            }
        }
    }

    /// Record every field path in `func` whose terminal member is declared as
    /// a POINTER.
    ///
    /// `extract_array_base` keeps a field path whole -- `u.int_array`,
    /// `pPg->aData` -- so two different paths read as two different arrays.
    /// That is right for an ARRAY member, which is storage of its own
    /// (ARR36-C-EX1), and wrong for a pointer member, whose target this frame
    /// cannot name any better than it can name a pointer parameter's
    /// (task 935). The member's declared type is what separates the two, so
    /// it is read rather than guessed at from the path.
    ///
    /// A path whose type does not resolve -- no `-d`, and no declaration in
    /// the file either -- is deliberately left as storage-naming. Absence of
    /// type information is not evidence that a member is a pointer, and
    /// treating it as such would switch off the EX1 detection wholesale on
    /// every single-file run.
    fn collect_pointer_members(
        &mut self,
        func: &Node,
        source: &str,
        struct_field_types: &HashMap<String, HashMap<String, String>>,
    ) {
        self.objects
            .record_pointer_members(func, source, struct_field_types);
    }

    fn process_declaration(&mut self, node: &Node, source: &str) {
        for declared in argument_objects::declared_pointers(node, source) {
            // Declared pointer or array. Recorded even when the base is
            // unknown (a bare `int *p;`), because a later `p = buf;` is
            // only trackable if we know p can hold a pointer at all.
            self.objects.note_declared(&declared);
            // Array declarations create their own storage — the variable IS its own base.
            if declared.is_array {
                self.variable_arrays
                    .insert(declared.name.clone(), declared.name);
                continue;
            }
            // Pointer with initializer: track which array it aliases.
            // A bare pointer declaration is not tracked -- we don't know what
            // it points to.
            let Some(value) = declared
                .init_declarator
                .and_then(|init| init.child_by_field_name("value"))
            else {
                continue;
            };
            let array_base = self.extract_array_base(&value, source);
            if !array_base.is_empty() {
                self.variable_arrays.insert(declared.name, array_base);
            }
        }
    }

    fn process_parameter(&mut self, node: &Node, source: &str) {
        // For function parameters, only track pointer/array parameters as distinct arrays.
        // Non-pointer parameters (int, uint32_t, etc.) are scalars — comparing them
        // is not pointer comparison and should not trigger ARR36-C.
        let Some(param_name) = self.objects.record_parameter(node, source) else {
            return;
        };
        // Use the parameter name itself as the "array base" to make it unique
        // This ensures parameters are only equal to themselves
        self.variable_arrays
            .insert(param_name.clone(), format!("param:{}", param_name));
    }

    /// Process simple assignment expressions like `slashPtr = strchr(string1, '/')`.
    /// Tracks variables assigned from string-search functions (strchr, strrchr,
    /// wcschr, wcsrchr) as pointing into the first argument's array.
    /// Skips compound assignments (+=, -=) since those advance a pointer within
    /// the same array rather than changing which array it points to.
    fn process_assignment(&mut self, node: &Node, source: &str) {
        // expression_statement contains an assignment_expression child
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "assignment_expression" {
                    // Skip compound assignments (+=, -=, etc.) — they advance a pointer
                    // within the same array rather than changing which array it points to.
                    // tree-sitter puts the operator as a direct child: "=", "+=", "-=", etc.
                    let mut is_simple_assign = false;
                    for j in 0..child.child_count() {
                        if let Some(op) = child.child(j) {
                            if ast_utils::get_node_text(&op, source) == "=" {
                                is_simple_assign = true;
                                break;
                            }
                        }
                    }
                    if !is_simple_assign {
                        continue;
                    }
                    if let (Some(left), Some(right)) = (
                        child.child_by_field_name("left"),
                        child.child_by_field_name("right"),
                    ) {
                        let var_name = ast_utils::get_node_text(&left, source).to_string();
                        if var_name.is_empty()
                            || !var_name.chars().all(|c| c.is_alphanumeric() || c == '_')
                        {
                            continue;
                        }
                        // Only a declared pointer or array can be IN an array.
                        // Without this gate an ordinary scalar swap --
                        // `startAngle = endAngle; endAngle = tmp;` over three
                        // floats -- puts both names in `variable_arrays`, and the
                        // subtraction below them is then reported as pointer
                        // subtraction between different arrays (task 769).
                        if !self.objects.pointer_vars.contains(&var_name) {
                            continue;
                        }
                        let array_base = self.extract_array_base(&right, source);
                        if !array_base.is_empty() {
                            self.variable_arrays.insert(var_name, array_base);
                        }
                    }
                }
            }
        }
    }

    fn extract_array_base(&self, node: &Node, source: &str) -> String {
        let result = match node.kind() {
            "identifier" => {
                let name = source[node.start_byte()..node.end_byte()].to_string();
                // Follow alias chain: if this variable is already tracked, use its base.
                // This ensures `pos = buf` gives pos the same base as buf (e.g., "param:buf").
                // Untracked identifiers return the raw name — they may be typedef arrays
                // or extern variables that weren't collected.
                if let Some(base) = self.variable_arrays.get(&name) {
                    base.clone()
                } else {
                    name
                }
            }
            "field_expression" => {
                // Handle struct.member or union.member - capture full path
                // This ensures u.int_array and u.float_array are distinct
                source[node.start_byte()..node.end_byte()].to_string()
            }
            "cast_expression" => {
                // Handle cast expressions like (int *)malloc(...) - unwrap to get the underlying value
                if let Some(value) = node.child_by_field_name("value") {
                    self.extract_array_base(&value, source)
                } else {
                    String::new()
                }
            }
            "call_expression" => {
                // Check if this is a string-search function (strchr, strrchr, wcschr, wcsrchr)
                // whose return value points into the first argument
                if let Some(func_node) = node.child_by_field_name("function") {
                    let func_name = ast_utils::get_node_text(&func_node, source);
                    // Recognize standard string-search functions and common
                    // wrapper macros (os_strchr, os_strstr, etc.)
                    let canonical = func_name.strip_prefix("os_").unwrap_or(func_name);
                    if matches!(
                        canonical,
                        "strchr"
                            | "strrchr"
                            | "wcschr"
                            | "wcsrchr"
                            | "memchr"
                            | "strstr"
                            | "wcsstr"
                            | "strpbrk"
                            | "wcspbrk"
                    ) {
                        // Return value points into the first argument
                        if let Some(args) = node.child_by_field_name("arguments") {
                            // First real argument (skip '(' which is child 0)
                            for j in 0..args.child_count() {
                                if let Some(arg) = args.child(j) {
                                    if arg.kind() != "(" && arg.kind() != ")" && arg.kind() != "," {
                                        return self.extract_array_base(&arg, source);
                                    }
                                }
                            }
                        }
                    }
                    // Allocation functions create distinct objects
                    if matches!(
                        canonical,
                        "malloc" | "calloc" | "realloc" | "aligned_alloc" | "alloca"
                    ) {
                        return format!("alloc@{}", node.start_byte());
                    }
                }
                // Other calls: unknown origin — don't assign a base.
                // Assigning a unique base would cause every unknown-call pointer
                // to mismatch with everything else, producing massive FPs.
                String::new()
            }
            "compound_literal_expression" => {
                // Handle compound literals like (int[]){1, 2, 3}
                // Each compound literal creates a distinct object
                // Use byte position to make each one unique, even if they have identical content
                format!(
                    "{}@{}",
                    &source[node.start_byte()..node.end_byte()],
                    node.start_byte()
                )
            }
            "string_literal" => {
                // Handle string literals like "Hello" and "World"
                // Each string literal creates a distinct array object
                // Use byte position to make each one unique, even if they have identical text
                format!(
                    "{}@{}",
                    &source[node.start_byte()..node.end_byte()],
                    node.start_byte()
                )
            }
            "binary_expression" => {
                // Handle pointer arithmetic like arr + size or ptr - offset
                // The base array is determined by the left operand
                if let Some(left) = node.child_by_field_name("left") {
                    self.extract_array_base(&left, source)
                } else {
                    String::new()
                }
            }
            "pointer_expression" | "unary_expression" => {
                self.extract_base_from_address_or_deref(node, source)
            }
            "subscript_expression" => {
                // Handle array subscripts like arrays[0], arrays[1]
                // Use the full expression to distinguish between different sub-arrays
                // This is important for multidimensional arrays where arrays[0] and arrays[1]
                // are different arrays even though they share the same base
                source[node.start_byte()..node.end_byte()].to_string()
            }
            _ => String::new(),
        };
        result
    }

    /// Base of `&x`, `&x.y`, `&x[i]` or `*p`. tree-sitter spells both `&` and
    /// `*` as a `pointer_expression`, so the operator is read off child 0.
    ///
    /// Address-of yields the object itself, so an untracked name IS its own
    /// base; dereference follows the alias chain and yields nothing when that
    /// chain is unknown.
    fn extract_base_from_address_or_deref(&self, node: &Node, source: &str) -> String {
        let is_address_of = node
            .child(0)
            .is_some_and(|op| ast_utils::get_node_text(&op, source) == "&");
        let Some(argument) = node.child_by_field_name("argument") else {
            return String::new();
        };
        let text = |n: &Node| source[n.start_byte()..n.end_byte()].to_string();

        match argument.kind() {
            // &var: the variable itself IS the array (single-element).
            "identifier" if is_address_of => self.resolve_base(text(&argument)),
            // *ptr: the result points into whatever the pointer points to.
            "identifier" => self
                .variable_arrays
                .get(&text(&argument))
                .cloned()
                .unwrap_or_default(),
            // &struct.member: keep just the struct instance, so two members of
            // one struct compare equal (ARR36-C-EX1).
            "field_expression" => match argument.child_by_field_name("argument") {
                Some(base) => self.resolve_base(text(&base)),
                None => text(&argument),
            },
            // &matrix[i][j] is based on "matrix", not "matrix[i]".
            "subscript_expression" => self.extract_deepest_base(&argument, source),
            _ => String::new(),
        }
    }

    fn extract_deepest_base(&self, node: &Node, source: &str) -> String {
        // Recursively extract the deepest base array from nested subscript expressions
        // For matrix[i][j], this returns "matrix"
        // For matrix[i], this returns "matrix"
        match node.kind() {
            "subscript_expression" => {
                if let Some(array) = node.child_by_field_name("argument") {
                    self.extract_deepest_base(&array, source)
                } else {
                    String::new()
                }
            }
            "identifier" => {
                self.resolve_base(source[node.start_byte()..node.end_byte()].to_string())
            }
            _ => String::new(),
        }
    }

    /// Canonicalize a base spelled as a bare name.
    ///
    /// `variable_arrays` holds a base under whatever spelling first recorded
    /// it -- `param:work` for a parameter, `pPg->aData` for a local aliasing a
    /// member -- so every path that produces a base from an identifier has to
    /// resolve it the same way. When one does not, the rule compares a base
    /// against ITSELF under two spellings and reports a violation: `workend =
    /// &work[N]` recorded `work` where the parameter had recorded
    /// `param:work`, and `pEnd = &aData[n]` recorded `aData` where the
    /// declaration had recorded `pPg->aData` (task 770).
    fn resolve_base(&self, name: String) -> String {
        match self.variable_arrays.get(&name) {
            Some(base) => base.clone(),
            None => name,
        }
    }

    /// Whether `*name` is still a pointer.
    ///
    /// A dereference spends one level of indirection. `*cursor` over a
    /// `u8 **cursor` is a pointer and keeps cursor's base; `*s` over a
    /// single-level `char *s` is the pointed-to VALUE and has no base at all,
    /// so `return *s1 - *s2;` is char arithmetic rather than pointer
    /// subtraction between two arrays (task 934).
    ///
    /// A name this frame never saw declared keeps the old reading. Absence of
    /// a recorded depth is not evidence of a depth -- the stance
    /// `record_pointer_members` already takes for a member whose type does not
    /// resolve.
    fn dereference_yields_pointer(&self, name: &str) -> bool {
        self.objects
            .pointer_depth
            .get(name)
            .is_none_or(|depth| *depth > 1)
    }

    fn get_pointer_info(&self, node: &Node, source: &str) -> Option<String> {
        match node.kind() {
            "identifier" => {
                let var_name = source[node.start_byte()..node.end_byte()].to_string();
                self.variable_arrays.get(&var_name).cloned()
            }
            "cast_expression" => {
                // Handle cast expressions like (int *)ptr - unwrap to get the underlying value
                if let Some(value) = node.child_by_field_name("value") {
                    self.get_pointer_info(&value, source)
                } else {
                    None
                }
            }
            "pointer_expression" | "unary_expression" => {
                // Handle &variable and *ptr patterns
                let is_address_of = node
                    .child(0)
                    .is_some_and(|op| ast_utils::get_node_text(&op, source) == "&");
                if let Some(argument) = node.child_by_field_name("argument") {
                    match argument.kind() {
                        "identifier" => {
                            let var_name =
                                source[argument.start_byte()..argument.end_byte()].to_string();
                            if is_address_of {
                                // &var: use tracked base or the variable name itself
                                Some(
                                    self.variable_arrays
                                        .get(&var_name)
                                        .cloned()
                                        .unwrap_or(var_name),
                                )
                            } else if self.dereference_yields_pointer(&var_name) {
                                // *ptr: follow alias chain
                                self.variable_arrays.get(&var_name).cloned()
                            } else {
                                None
                            }
                        }
                        "field_expression" => {
                            let field_path =
                                source[argument.start_byte()..argument.end_byte()].to_string();
                            if is_address_of {
                                Some(
                                    self.variable_arrays
                                        .get(&field_path)
                                        .cloned()
                                        .unwrap_or(field_path),
                                )
                            } else {
                                self.variable_arrays.get(&field_path).cloned()
                            }
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            }
            "field_expression" => {
                // Handle struct.member or union.member access
                // Only return info if explicitly tracked — don't assume all field
                // expressions are pointers. Untracked fields (integers, etc.)
                // should return None to avoid flagging scalar comparisons.
                let var_name = source[node.start_byte()..node.end_byte()].to_string();
                self.variable_arrays.get(&var_name).cloned()
            }
            _ => None,
        }
    }
}

/// The struct field types in scope for one file: the prescan's project-wide
/// map, overlaid with the declarations the file makes itself.
///
/// The file's own pass is what keeps the member-type test working on a run
/// with no `-d`, where `project` is empty -- the canonical
/// cross-file-OR-same-file wiring. The project map is borrowed rather than
/// copied when the file declares no structs of its own, which is the common
/// case for a `.c` file that includes its headers.
fn merge_file_struct_fields<'a>(
    project: &'a HashMap<String, HashMap<String, String>>,
    project_aliases: &HashMap<String, String>,
    node: &Node,
    source: &str,
) -> Cow<'a, HashMap<String, HashMap<String, String>>> {
    let mut local = HashMap::new();
    prescan::collect_struct_definitions(node, source, &mut local);
    let mut local_aliases = HashMap::new();
    prescan::collect_struct_typedef_aliases(node, source, &mut local_aliases);

    let mut merged = if local.is_empty() {
        Cow::Borrowed(project)
    } else if project.is_empty() {
        Cow::Owned(local)
    } else {
        let mut merged = Cow::Borrowed(project);
        merged.to_mut().extend(local);
        merged
    };

    // `typedef struct sqlite3_value Mem;` files the fields under the TAG, so a
    // member reached as `pOut->z` on a `Mem *` resolves only once the alias
    // names the same field set. Done here, on the rule's own view of the map,
    // rather than in the prescan's `struct_field_types`: that map is read by
    // four other rules, and this must not move their finding sets.
    let additions: Vec<(String, HashMap<String, String>)> = project_aliases
        .iter()
        .chain(local_aliases.iter())
        .filter(|(alias, _)| !merged.contains_key(alias.as_str()))
        .filter_map(|(alias, tag)| Some((alias.clone(), merged.get(tag)?.clone())))
        .collect();
    if !additions.is_empty() {
        merged.to_mut().extend(additions);
    }
    merged
}

fn get_operator(node: &Node, source: &str) -> Option<String> {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            let text = source[child.start_byte()..child.end_byte()].to_string();
            if matches!(text.as_str(), "-" | "<" | "<=" | ">" | ">=") {
                return Some(text);
            }
        }
    }
    None
}
