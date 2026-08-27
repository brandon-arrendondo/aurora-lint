use super::function_summary::FunctionSummary;
use super::macro_expand::FunctionMacro;
use super::null_state::NullState;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Cross-file context gathered by pre-scanning additional directories.
///
/// Holds function names found in `.c`/`.h` files so that rules like DCL31-C
/// and DCL07-C can suppress false positives for project-internal functions
/// defined in other translation units.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProjectContext {
    /// Every function name found in the pre-scanned `.c`/`.h` files.
    pub known_functions: HashSet<String>,
    /// Functions declared (prototyped) in `.h` header files.
    /// A function with a header prototype is public API and should not be
    /// flagged by DCL15-C/DCL19-C as needing `static`.
    pub header_declared_functions: HashSet<String>,
    /// Function summaries computed during prescan for inter-procedural analysis.
    pub function_summaries: HashMap<String, FunctionSummary>,
    /// Call graph: maps function name to the set of functions it calls.
    pub call_graph: HashMap<String, HashSet<String>>,
    /// Callee names that must never be resolved to a same-named function
    /// definition by name matching alone: names reached only through a
    /// `field_expression` call (`obj->cb(...)`) or through a plain
    /// identifier that is also a parameter name of the calling function
    /// (a callback passed by the caller, shadowing any same-named global
    /// function per C scoping rules). `call_graph` may still contain edges
    /// to these names (recorded by the underlying, name-matching-only call
    /// graph builder), so a consumer doing cycle/reachability analysis
    /// through unresolved indirect calls should treat any callee in this
    /// set as opaque rather than chase it (task 562).
    #[serde(default)]
    pub ambiguous_call_targets: HashSet<String>,
    /// Macro constants collected from `#define` directives across all scanned files.
    pub macro_constants: HashMap<String, i64>,
    /// Macro aliases: `#define ALIAS identifier` patterns (e.g., `SYSTEM` → `system`).
    /// Used by rules to resolve function calls through macro indirection.
    pub macro_aliases: HashMap<String, String>,
    /// Struct field types: maps `struct_name -> field_name -> type_text`.
    /// Enables resolving types of `field_expression` nodes (e.g., `s->count` → "int").
    pub struct_field_types: HashMap<String, HashMap<String, String>>,
    /// Names of struct (and typedef-aliased) types declared
    /// `__attribute__((packed))` (directly or via a macro like
    /// `STRUCT_PACKED` whose `#define` expands to packed) across all scanned
    /// files, incl. headers. A packed struct's actual alignment is 1, so
    /// EXP36-C must not treat a cast into it as alignment-increasing.
    #[serde(default)]
    pub packed_structs: HashSet<String>,
    /// Global constants: `[const] TYPE NAME = VALUE;` from across all scanned files.
    /// Used by init-state analysis for dead-branch elimination.
    #[serde(default)]
    pub global_constants: HashMap<String, i64>,
    /// Global pointer variable null states from across all scanned files.
    /// Maps variable name to its joined null state across all assignment sites.
    /// Used by EXP34-C to resolve `extern` pointer globals declared in other
    /// translation units (Juliet CWE-476 variant 68 pattern).
    #[serde(default)]
    pub global_var_null_states: HashMap<String, NullState>,
    /// File-scope `static` variable writers: maps static-variable name to the
    /// set of function names that assign to it. Used by ENV03-C (and other
    /// taint-aware rules) to decide whether a `char *data = g_static;` read
    /// brings in taint — if every writer's summary is taint-free, the global
    /// is treated as clean. Targets Juliet CWE-78 variant 45 (goodG2BSink
    /// pattern).
    #[serde(default)]
    pub global_writers: HashMap<String, HashSet<String>>,
    /// Function-like macro definitions (`#define NAME(a,b) body`) collected
    /// across all scanned files (incl. headers) during the prescan pre-pass.
    /// Consumed by `macro_expand` to expand opaque macro invocations on demand
    /// (Phase 2 of docs/design/macro-expansion.md). Macros using `#`/`##` or
    /// variadics are intentionally excluded (see `macro_expand`).
    #[serde(default)]
    pub function_macros: HashMap<String, FunctionMacro>,
    /// Names of every `#define NAME ...` object-like macro collected across
    /// all scanned files (incl. headers), regardless of what they expand to.
    /// Used by DCL40-C to recognize a trailing bare identifier after a
    /// struct/union/enum body (e.g. hostap's `struct foo { ... }
    /// STRUCT_PACKED;`) as an attribute-position macro invocation rather
    /// than a genuine object declaration — the `#define` commonly lives in a
    /// different file than the struct (task 432).
    #[serde(default)]
    pub defined_macro_names: HashSet<String>,
    /// Functions whose name appears as a bare value inside an aggregate
    /// initializer (e.g. `{ "mysql", pw_mysql_parse, pw_mysql_check,
    /// pw_mysql_exit }` or a designated `.check = pw_mysql_check`) — the
    /// dispatch-table registration idiom used by callback-style backends
    /// (auth/log/protocol handler tables) — and that are never invoked
    /// through a direct-by-name `identifier(...)` call anywhere in the
    /// project. Such a function is reachable only through the single
    /// indirect call site that walks the table, so API00-C treats it like
    /// a project-internal helper (task 594, extending task 169's
    /// internal-contract suppression to the dispatch-table-callback shape).
    #[serde(default)]
    pub dispatch_table_callbacks: HashSet<String>,
}

impl ProjectContext {
    /// An empty context, as if nothing had been pre-scanned yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if the given name was found during the pre-scan.
    pub fn is_known_function(&self, name: &str) -> bool {
        self.known_functions.contains(name)
    }

    /// Returns the summary for a function, if available.
    pub fn get_function_summary(&self, name: &str) -> Option<&FunctionSummary> {
        self.function_summaries.get(name)
    }

    /// Returns `true` if the function has a prototype in a `.h` header file,
    /// indicating it is public API with intentional external linkage.
    pub fn is_header_declared(&self, name: &str) -> bool {
        self.header_declared_functions.contains(name)
    }

    /// Look up the type of a struct field given the struct name and field name.
    /// `struct_name` should be the bare name (e.g., "MyStruct", not "struct MyStruct").
    pub fn get_struct_field_type(&self, struct_name: &str, field_name: &str) -> Option<&str> {
        self.struct_field_types
            .get(struct_name)
            .and_then(|fields| fields.get(field_name))
            .map(|s| s.as_str())
    }

    /// Returns `true` if any cross-file data was collected.
    ///
    /// `header_declared_functions` is included so that a lightweight
    /// header-only prescan (no `-d` flag) still triggers `set_project_context`
    /// on rules like DCL15-C that only need the public-API declaration set.
    pub fn has_cross_file_data(&self) -> bool {
        !self.known_functions.is_empty()
            || !self.function_summaries.is_empty()
            || !self.macro_constants.is_empty()
            || !self.struct_field_types.is_empty()
            || !self.header_declared_functions.is_empty()
    }

    /// Save prescan context to a binary cache file.
    pub fn save_to_file(&self, path: &Path) -> anyhow::Result<()> {
        let encoded = bincode::serialize(self)?;
        std::fs::write(path, &encoded)?;
        Ok(())
    }

    /// Load prescan context from a binary cache file.
    pub fn load_from_file(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read(path)?;
        let context: Self = bincode::deserialize(&data)?;
        Ok(context)
    }
}
