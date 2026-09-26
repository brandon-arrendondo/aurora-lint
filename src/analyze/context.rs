use super::function_summary::FunctionSummary;
use super::macro_expand::FunctionMacro;
use super::null_state::NullState;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

/// Cross-file context gathered by pre-scanning additional directories.
///
/// Holds function names found in `.c`/`.h` files so that rules like DCL31-C
/// and DCL07-C can suppress false positives for project-internal functions
/// defined in other translation units.
///
/// The tables are `Arc`-wrapped because every scanned file hands this context
/// to a fresh set of rule instances, each of which keeps its own handle
/// (`set_project_context`). A handle is a refcount bump; a deep copy of the
/// function summaries of a few-thousand-file project, per rule, per file, was
/// the dominant cost of a scan. Build the tables in full, then wrap; after
/// that, mutate only through `Arc::make_mut` and only before rules see the
/// context (`resolve_includes`, the compile-database merge).
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProjectContext {
    /// The policy and environment settings this run analyzes under.
    ///
    /// Never serialized: a prescan records facts about the code (which
    /// functions are declared `_Noreturn`, which are verified never to
    /// return), and the settings decide what a rule may conclude from them.
    /// A cache saved under one setting is therefore valid under every other,
    /// and must stay so -- a table that bakes a setting in would need the
    /// cache to record it.
    #[serde(skip)]
    pub settings: Arc<crate::settings::AnalysisSettings>,
    /// Every function name found in the pre-scanned `.c`/`.h` files.
    pub known_functions: Arc<HashSet<String>>,
    /// Functions declared (prototyped) in `.h` header files.
    /// A function with a header prototype is public API and should not be
    /// flagged by DCL15-C/DCL19-C as needing `static`.
    pub header_declared_functions: Arc<HashSet<String>>,
    /// Function summaries computed during prescan for inter-procedural analysis.
    pub function_summaries: ScopedTable<FunctionSummary>,
    /// Call graph: maps function name to the set of functions it calls.
    pub call_graph: Arc<HashMap<String, HashSet<String>>>,
    /// The inverse of `call_graph`: maps a function name to the set of
    /// functions that call it. Computed once when the context is built, so
    /// a rule asking "who calls this?" per file does not re-invert the whole
    /// graph per file (six rules did, each on every file).
    #[serde(default)]
    pub callers: Arc<HashMap<String, HashSet<String>>>,
    /// Callee names that must never be resolved to a same-named function
    /// definition by name matching alone: names reached only through a
    /// `field_expression` call (`obj->cb(...)`) or through a plain
    /// identifier that is also a parameter name of the calling function
    /// (a callback passed by the caller, shadowing any same-named global
    /// function per C scoping rules). `call_graph` may still contain edges
    /// to these names (recorded by the underlying, name-matching-only call
    /// graph builder), so a consumer doing cycle/reachability analysis
    /// through unresolved indirect calls should treat any callee in this
    /// set as opaque rather than chase it.
    #[serde(default)]
    pub ambiguous_call_targets: Arc<HashSet<String>>,
    /// Macro constants collected from `#define` directives across all scanned files.
    pub macro_constants: Arc<HashMap<String, i64>>,
    /// Macro aliases: `#define ALIAS identifier` patterns (e.g., `SYSTEM` → `system`).
    /// Used by rules to resolve function calls through macro indirection.
    pub macro_aliases: Arc<HashMap<String, String>>,
    /// Struct field types: maps `struct_name -> field_name -> type_text`.
    /// Enables resolving types of `field_expression` nodes (e.g., `s->count` → "int").
    pub struct_field_types: Arc<HashMap<String, HashMap<String, String>>>,
    /// Names of struct (and typedef-aliased) types declared
    /// `__attribute__((packed))` (directly or via a macro like
    /// `STRUCT_PACKED` whose `#define` expands to packed) across all scanned
    /// files, incl. headers. A packed struct's actual alignment is 1, so
    /// EXP36-C must not treat a cast into it as alignment-increasing.
    #[serde(default)]
    pub packed_structs: Arc<HashSet<String>>,
    /// Names of functions known never to return to their caller, collected
    /// across all scanned files (incl. headers) by
    /// [`crate::analyze::noreturn::collect_noreturn_names`]: the fixed C
    /// standard library set, `_Noreturn` qualifiers, and definitions
    /// verified never to return -- once per combination of
    /// `trust_noreturn_keyword` and `stdlib_noreturn`; a reader picks one with
    /// [`ByNoreturnTrust::get`](crate::analyze::noreturn::ByNoreturnTrust::get).
    /// Cross-file because the declaration carrying the keyword is routinely
    /// in a header the single-file parse never sees.
    #[serde(default)]
    pub noreturn_functions: crate::analyze::noreturn::ByNoreturnTrust<Arc<HashSet<String>>>,
    /// Global constants: `[const] TYPE NAME = VALUE;` from across all scanned files.
    /// Used by init-state analysis for dead-branch elimination.
    #[serde(default)]
    pub global_constants: HashMap<String, i64>,
    /// Global pointer variable null states from across all scanned files.
    /// Maps variable name to its joined null state across all assignment sites.
    /// Used by EXP34-C to resolve `extern` pointer globals declared in other
    /// translation units (Juliet CWE-476 variant 68 pattern).
    #[serde(default)]
    pub global_var_null_states: Arc<HashMap<String, NullState>>,
    /// File-scope `static` variable writers: maps static-variable name to the
    /// set of function names that assign to it. Used by ENV03-C (and other
    /// taint-aware rules) to decide whether a `char *data = g_static;` read
    /// brings in taint — if every writer's summary is taint-free, the global
    /// is treated as clean. Targets Juliet CWE-78 variant 45 (goodG2BSink
    /// pattern).
    #[serde(default)]
    pub global_writers: Arc<HashMap<String, HashSet<String>>>,
    /// Function-like macro definitions (`#define NAME(a,b) body`) collected
    /// across all scanned files (incl. headers) during the prescan pre-pass.
    /// Consumed by `macro_expand` to expand opaque macro invocations on demand
    /// (Phase 2 of docs/design/macro-expansion.md). Macros using `#`/`##` or
    /// variadics are intentionally excluded (see `macro_expand`).
    #[serde(default)]
    pub function_macros: Arc<HashMap<String, FunctionMacro>>,
    /// Every `#define` of every name across all scanned files (incl.
    /// headers), in every preprocessor arm the file does not itself prove
    /// dead, each distinct definition kept. Raw material for
    /// [`abort_check_macros`](Self::abort_check_macros), which must see every
    /// alternative, not the one `function_macros` keeps.
    #[serde(default)]
    pub macro_definitions: Arc<HashMap<String, Vec<crate::analyze::check_macros::MacroDefinition>>>,
    /// Names `#define`d inside a live `#if`/`#ifdef`/`#ifndef` arm of any
    /// scanned file or header, per
    /// [`crate::analyze::check_macros::collect_conditional_macro_names`]: a
    /// configuration exists in which that definition is absent, so what the
    /// name expands to is not settled by `macro_definitions` alone.
    #[serde(default)]
    pub conditional_macro_names: Arc<HashSet<String>>,
    /// `macro name -> index of the parameter it checks`, for the assert-style
    /// macros no configuration compiles out (valkey's `serverAssert`), per
    /// [`crate::analyze::check_macros::abort_check_macros`], under each
    /// noreturn setting ([`crate::analyze::noreturn::ByNoreturnTrust`]:
    /// whether a macro's failure path
    /// ends depends on which functions count as noreturn). Recomputed
    /// whenever `macro_definitions` or `noreturn_functions` grows.
    #[serde(default)]
    pub abort_check_macros: crate::analyze::noreturn::ByNoreturnTrust<Arc<HashMap<String, usize>>>,
    /// Names of every `#define NAME ...` object-like macro collected across
    /// all scanned files (incl. headers), regardless of what they expand to.
    /// Used by DCL40-C to recognize a trailing bare identifier after a
    /// struct/union/enum body (e.g. hostap's `struct foo { ... }
    /// STRUCT_PACKED;`) as an attribute-position macro invocation rather
    /// than a genuine object declaration — the `#define` commonly lives in a
    /// different file than the struct.
    #[serde(default)]
    pub defined_macro_names: Arc<HashSet<String>>,
    /// Names of every object-like `#define` whose replacement text is an
    /// unused-attribute annotation — `__attribute__((unused))`,
    /// `[[maybe_unused]]`, and the reserved spellings — collected across all
    /// scanned files (incl. headers). seL4's `UNUSED`, hostap's
    /// `STRUCT_PACKED`-adjacent annotations and the rest are recognized by
    /// what they *expand to*, never by name, and the `#define` almost always
    /// lives in a different file from the declaration it annotates.
    ///
    /// Used by MSC13-C: aurora-lint has no preprocessor, so such a macro sits
    /// in the declaration where a type or declarator is expected and the
    /// recovered parse misnames the variable. The annotation is the author
    /// stating the variable may legitimately go unused, which is exactly
    /// what MSC13-C exists to respect, so a declaration carrying one is not
    /// reported at all.
    #[serde(default)]
    pub unused_attribute_macros: Arc<HashSet<String>>,
    /// Functions whose name appears as a bare value inside an aggregate
    /// initializer (e.g. `{ "mysql", pw_mysql_parse, pw_mysql_check,
    /// pw_mysql_exit }` or a designated `.check = pw_mysql_check`) — the
    /// dispatch-table registration idiom used by callback-style backends
    /// (auth/log/protocol handler tables) — and that are never invoked
    /// through a direct-by-name `identifier(...)` call anywhere in the
    /// project. Such a function is reachable only through the single
    /// indirect call site that walks the table, so API00-C treats it like
    /// a project-internal helper (extending an earlier internal-contract
    /// suppression to the dispatch-table-callback shape).
    #[serde(default)]
    pub dispatch_table_callbacks: HashSet<String>,
    /// `#include` paths that name a *project* header which is not on disk:
    /// the directory prefix resolves under one of the search roots but the
    /// file itself does not exist (e.g. seL4's `<object/structures_gen.h>`,
    /// emitted at build time by `tools/bitfield_gen.py` from an `.bf` spec;
    /// likewise `*.pb-c.h`, `*.tab.h`, and other generated headers).
    ///
    /// A system header that simply isn't on the `-I` path (`<sys/socket.h>`)
    /// does *not* land here — its directory prefix doesn't exist under the
    /// project either — so this set means specifically "this project's
    /// declaration set is incomplete because a build step we can't run
    /// produces part of it".
    #[serde(default)]
    pub unresolved_project_headers: HashSet<String>,
    /// Every place the macro-expansion engine declined or failed to see a
    /// definition while building this context — skipped variadic / `#`/`##`
    /// macros, platform-dead and ambiguous definitions, cross-file conflicts,
    /// unresolvable `#include`s. Recorded unconditionally (it is a by-product
    /// of scans that already run) and surfaced only by `--report-macro-gaps`;
    /// nothing in analysis reads it.
    #[serde(default)]
    pub macro_gaps: Vec<super::macro_gaps::MacroGap>,
    /// `function name -> indices of its restrict-qualified parameters`, for
    /// every function any scanned file defines or declares with at least one.
    /// First definition seen wins. Lets EXP43-C confine its aliasing check
    /// to callees whose contract actually forbids aliasing.
    #[serde(default)]
    pub restrict_params: HashMap<String, Vec<usize>>,
    /// `function name -> indices of the parameters whose doc comment states
    /// a non-NULL precondition` ("must be initialized", "must not be NULL",
    /// ...), from every definition and prototype any scanned file carries a
    /// Doxygen comment for. The function's own published contract, which is
    /// what lets API00-C and the EXP34-C parameter seeding honour a
    /// caller-validates discipline the code documents.
    #[serde(default)]
    pub documented_nonnull_params: HashMap<String, Vec<usize>>,
    /// Function names reachable (including the root itself) from a real
    /// concurrent-execution root: an ISR handler, a thread-spawn entry
    /// point (`pthread_create`/`thrd_create`/`CreateThread`, direct or
    /// forwarded through a function-like macro), or a `signal()`-registered
    /// handler. Computed once during prescan by forward-walking
    /// `call_graph` from every detected root (`ambiguous_call_targets`
    /// edges excluded — see that field's docs). Empty when the scanned
    /// project has no such root anywhere (e.g. a genuinely single-threaded
    /// codebase). Used by CON03-C/CON07-C to gate findings on whether the
    /// flagged code is ever reachable from a concurrent context at all,
    /// rather than firing unconditionally (see
    /// `docs/design/con03-con07-isr-thread-reachability.md`).
    #[serde(default)]
    pub concurrency_reachable: Arc<HashSet<String>>,
    /// Names of project-wide (file-scope, non-local) variables declared with
    /// a plain, non-pointer/non-array/non-function type -- across every
    /// scanned `.c` AND `.h` file, extern declarations included, since the
    /// `extern` forward-declaration and the actual definition are typically
    /// in different files. A name is excluded if it is ever declared with a
    /// pointer or array declarator anywhere in the project (conservative:
    /// only one true global object can exist per name at link time, so
    /// disagreement means something this heuristic shouldn't guess about).
    ///
    /// Mirrors MEM31-C's per-function `value_only_locals`
    /// (`collect_value_only_locals`) but at project scope: seL4's
    /// `current_lookup_fault`/`current_fault` globals are `extern`-declared
    /// in a header and assigned via a bitfield-generator `_new()` value
    /// constructor (`current_lookup_fault = lookup_fault_new(...)`) from
    /// several other translation units, with no local declaration in any of
    /// them -- MEM31-C's per-function pointer-evidence guard can't see a
    /// declaration at all in that shape, so it needs this project-wide set
    /// instead.
    #[serde(default)]
    pub value_only_globals: Arc<HashSet<String>>,
    /// Struct/union typedef aliases: `alias name -> the tag name its fields
    /// are filed under in `struct_field_types``, for every
    /// `typedef struct Tag Alias;` across the scanned files.
    ///
    /// `collect_from_typedef` files a BODIED typedef under both the tag and
    /// the alias, so the gap this closes is the bodyless spelling:
    /// sqlite's `vdbe.h` says `typedef struct sqlite3_value Mem;` while
    /// `vdbeInt.h` declares `struct sqlite3_value { ... }`, so the fields are
    /// filed under `sqlite3_value` and nothing maps `Mem` onto them. The
    /// typedef and the use are routinely in different files, so no file-local
    /// pass can close it.
    ///
    /// Deliberately kept OUT of `struct_field_types` itself. That map is read
    /// by INT30-C, INT32-C, INT33-C and FLP03-C, and filing the alias there
    /// would move four other rules' finding sets as a side effect of an
    /// ARR36-C fix; a consumer opts in by resolving through this map, which
    /// so far only ARR36-C does.
    #[serde(default)]
    pub struct_typedef_aliases: Arc<HashMap<String, String>>,
    /// One-level `typedef` alias map: `alias name -> underlying type text as
    /// written` (e.g. `"paddr_t" -> "word_t"`, `"word_t" -> "unsigned long"`),
    /// collected across every scanned `.c`/`.h` file. Simple scalar aliases
    /// only (`typedef <type> <name>;`) -- struct/union/enum-bodied typedefs
    /// are tracked separately by `struct_field_types`, and pointer/array/
    /// function typedefs are excluded since they don't participate in a
    /// scalar signedness chain.
    ///
    /// A typedef's declaring header is frequently not the file that uses the
    /// alias (seL4's `word_t` family: `paddr_t`/`pptr_t`/`vptr_t`/`seL4_Word`
    /// each typedef onto `word_t`, sometimes from an arch-specific header
    /// different from where `word_t` itself is defined), so resolving one
    /// level locally isn't enough -- a consumer must walk this map
    /// recursively (see `overflow_helpers::typedef_chain_is_unsigned`) and
    /// project-wide.
    #[serde(default)]
    pub typedef_types: Arc<HashMap<String, String>>,
    /// Names of typedefs whose declared type is a function pointer -- e.g.
    /// sqlite's `typedef int (*RecordCompare)(void *, int);` in
    /// `sqliteInt.h`. `collect_from_simple_typedef` filed under
    /// `typedef_types` only stores primitive/sized/named RHSs, so a
    /// function-pointer typedef leaves that map with no entry for its
    /// alias name; DCL31-C needs the *category* (function-pointer
    /// typedef?), not the RHS text, to decide whether a parameter of
    /// that type is directly callable (second consumer of
    /// an earlier fix's shared typedef-chain resolver).
    #[serde(default)]
    pub function_pointer_typedef_names: Arc<HashSet<String>>,
    /// Names of typedefs that hide a pointer in DCL05-C's sense -- a pointer
    /// in the declarator chain, not a function pointer, not a pointer to
    /// const (`declarator_utils::pointer_typedef_names_in`). The typedef is
    /// usually in a header; the `const LPPOINT pt` parameter that the rule
    /// is about is in a .c file that only names the alias.
    #[serde(default)]
    pub pointer_typedef_names: Arc<HashSet<String>>,
    /// `file -> the names that file defines `static` while some other
    /// scanned file does too`: the files whose view of
    /// `function_summaries` is not the shared one.
    ///
    /// Two `static` definitions of one bare name are two unrelated
    /// functions (mbedtls' two `psa_aead_setup`, sqlite's three
    /// `SHA3Update`), so neither may answer under the bare name: whichever
    /// the fold reached first used to answer for every caller in the
    /// project, including the files that define the other one. Each is
    /// kept under its (file, name) key instead, and [`Self::as_seen_from`]
    /// resolves a file's own spelling of the name to its own definition. A
    /// name with no external definition anywhere has no bare entry at all,
    /// which is the sound answer for a caller in neither file -- it cannot
    /// legally call either definition
    /// (`docs/design/multiply-defined-names.md`).
    ///
    /// Keys are canonicalized, because the walk that fills this and the walk
    /// that looks it up need not spell a path the same way.
    #[serde(default)]
    pub scoped_names_by_file: Arc<HashMap<String, Arc<HashSet<String>>>>,
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
            || !self.typedef_types.is_empty()
    }

    /// This context as the file at `path` may use it, or `None` when that is
    /// this context unchanged -- which is every file but the handful that
    /// define a name some other file also defines `static`.
    ///
    /// The returned view differs in one table, `function_summaries`: this
    /// file's spelling of such a name resolves to its own definition. The
    /// view is a scope over the shared table, not a copy of it. It used to be a copy of the summary map, which was
    /// cheap only while few files needed one; in Juliet nearly every file
    /// defines a `static void goodG2B()`, and the copy per file cost more
    /// than the rules did.
    pub fn as_seen_from(&self, path: &Path) -> Option<Self> {
        if self.scoped_names_by_file.is_empty() {
            return None;
        }
        let key = crate::analyze::compile_commands::real_path(path);
        let names = self.scoped_names_by_file.get(&key)?;
        let scope = FileScope {
            file: Arc::from(key.as_str()),
            names: Arc::clone(names),
        };
        Some(Self {
            function_summaries: self.function_summaries.scoped(scope),
            ..self.clone()
        })
    }

    /// Save prescan context to a binary cache file.
    pub fn save_to_file(&self, path: &Path) -> anyhow::Result<()> {
        let mut encoded = cache_header().into_bytes();
        encoded.extend(bincode::serialize(self)?);
        std::fs::write(path, &encoded)?;
        Ok(())
    }

    /// Load prescan context from a binary cache file. A cache written by a
    /// different format or aurora-lint version is refused by its header:
    /// bincode is not self-describing, so reading one would fail at best and
    /// silently misread fields at worst.
    pub fn load_from_file(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read(path)?;
        let header = cache_header();
        let Some(body) = data.strip_prefix(header.as_bytes()) else {
            anyhow::bail!(
                "prescan cache {} was written by a different aurora-lint build or cache \
                 format (expected header {:?}); re-create it with --save-prescan",
                path.display(),
                header.trim_end()
            );
        };
        let context: Self = bincode::deserialize(body)?;
        Ok(context)
    }
}

/// Version of the prescan cache's serialized layout. Bump it with any change
/// to a serialized field of [`ProjectContext`] (or of a type it holds): the
/// cache header carries it, so an old cache is refused instead of misread.
const PRESCAN_CACHE_FORMAT: u32 = 2;

/// The header a prescan cache file starts with: a magic, the layout version
/// and the aurora-lint version that wrote it.
fn cache_header() -> String {
    format!(
        "aurora-lint-prescan format={} version={}\n",
        PRESCAN_CACHE_FORMAT,
        env!("CARGO_PKG_VERSION")
    )
}

/// The key a (file, name) pair is stored under in a [`ScopedTable`]: a name
/// defined `static` in several scanned files, qualified by the one file whose
/// definition it is. The NUL cannot occur in a C identifier or in a path, so
/// no bare lookup ever lands on one.
pub fn qualified_key(file: &str, name: &str) -> String {
    format!("{file}\0{name}")
}

/// Which file a [`ScopedTable`] is being read from, and the names that file
/// resolves to its own definitions.
#[derive(Debug, Clone)]
pub struct FileScope {
    file: Arc<str>,
    names: Arc<HashSet<String>>,
}

/// A name-keyed project table in which a name several files define `static`
/// is held once per defining file, and read through a file's scope.
///
/// Unscoped, a bare name reads the bare entry and no file's own entries are
/// visible to iteration. Scoped to a file, a bare name that file defines
/// `static` reads that file's own entry instead. A [`qualified_key`] read
/// directly reaches its entry from any scope: that is how a walk that has
/// already resolved a caller to its defining file -- `callers` hands out
/// qualified keys for exactly those callers -- reads that caller's summary
/// from a file that is not its own.
///
/// The per-file entries are held apart from the bare ones, so iterating a
/// scope costs what iterating the old per-file copy did: the bare entries
/// plus this file's own, not every file's.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(bound(
    serialize = "V: serde::Serialize",
    deserialize = "V: serde::Deserialize<'de>"
))]
pub struct ScopedTable<V> {
    entries: Arc<HashMap<String, V>>,
    by_file: Arc<HashMap<String, HashMap<String, V>>>,
    #[serde(skip)]
    scope: Option<FileScope>,
}

impl<V> Default for ScopedTable<V> {
    fn default() -> Self {
        Self {
            entries: Arc::new(HashMap::new()),
            by_file: Arc::new(HashMap::new()),
            scope: None,
        }
    }
}

impl<V> From<HashMap<String, V>> for ScopedTable<V> {
    /// Splits `entries` on [`qualified_key`]: a qualified key goes to its
    /// file's own entries, every other key stays bare.
    fn from(entries: HashMap<String, V>) -> Self {
        let mut bare = HashMap::with_capacity(entries.len());
        let mut by_file: HashMap<String, HashMap<String, V>> = HashMap::new();
        for (key, value) in entries {
            match key.split_once('\0') {
                Some((file, name)) => {
                    by_file
                        .entry(file.to_string())
                        .or_default()
                        .insert(name.to_string(), value);
                }
                None => {
                    bare.insert(key, value);
                }
            }
        }
        Self {
            entries: Arc::new(bare),
            by_file: Arc::new(by_file),
            scope: None,
        }
    }
}

impl<V> ScopedTable<V> {
    /// The shared bare entries, for prescan's own passes that finish a
    /// context before any rule reads it. Copy-on-write, like every other
    /// table.
    pub fn make_mut(&mut self) -> &mut HashMap<String, V>
    where
        V: Clone,
    {
        Arc::make_mut(&mut self.entries)
    }

    /// This table as `scope`'s file reads it. A handle, not a copy.
    pub fn scoped(&self, scope: FileScope) -> Self {
        Self {
            entries: Arc::clone(&self.entries),
            by_file: Arc::clone(&self.by_file),
            scope: Some(scope),
        }
    }

    /// The entry `name` resolves to from this scope.
    pub fn get(&self, name: &str) -> Option<&V> {
        if let Some((file, bare)) = name.split_once('\0') {
            return self.by_file.get(file)?.get(bare);
        }
        match &self.scope {
            Some(scope) if scope.names.contains(name) => self.by_file.get(&*scope.file)?.get(name),
            _ => self.entries.get(name),
        }
    }

    /// Whether `name` resolves to an entry from this scope.
    pub fn contains_key(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Whether the prescan produced no entries at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.by_file.is_empty()
    }

    /// Every entry this scope can name, under the name it would use: the
    /// bare entries it does not shadow and its own file's.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &V)> + '_ {
        let own = self
            .scope
            .as_ref()
            .and_then(|scope| self.by_file.get(&*scope.file));
        self.entries
            .iter()
            .filter(move |(key, _)| {
                self.scope
                    .as_ref()
                    .is_none_or(|scope| !scope.names.contains(key.as_str()))
            })
            .chain(own.into_iter().flatten())
    }

    /// How many entries [`Self::iter`] yields.
    pub fn len(&self) -> usize {
        self.iter().count()
    }
}

/// A function-summary lookup by name, whichever table answers it: prescan's
/// own map while it is still building one, or a [`ScopedTable`] as a file's
/// rules see it.
pub trait SummaryLookup {
    /// The summary `name` resolves to.
    fn get(&self, name: &str) -> Option<&FunctionSummary>;

    /// Whether `name` resolves to a summary.
    fn contains_key(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Whether there is no summary at all.
    fn is_empty(&self) -> bool;

    /// Every (name, summary) this lookup answers, each name once.
    fn entries(&self) -> Box<dyn Iterator<Item = (&String, &FunctionSummary)> + '_>;
}

impl SummaryLookup for HashMap<String, FunctionSummary> {
    fn get(&self, name: &str) -> Option<&FunctionSummary> {
        HashMap::get(self, name)
    }

    fn is_empty(&self) -> bool {
        HashMap::is_empty(self)
    }

    fn entries(&self) -> Box<dyn Iterator<Item = (&String, &FunctionSummary)> + '_> {
        Box::new(self.iter())
    }
}

impl SummaryLookup for ScopedTable<FunctionSummary> {
    fn get(&self, name: &str) -> Option<&FunctionSummary> {
        ScopedTable::get(self, name)
    }

    fn is_empty(&self) -> bool {
        ScopedTable::is_empty(self)
    }

    fn entries(&self) -> Box<dyn Iterator<Item = (&String, &FunctionSummary)> + '_> {
        Box::new(self.iter())
    }
}

impl<T: SummaryLookup + ?Sized> SummaryLookup for std::cell::Ref<'_, T> {
    fn get(&self, name: &str) -> Option<&FunctionSummary> {
        (**self).get(name)
    }

    fn is_empty(&self) -> bool {
        (**self).is_empty()
    }

    fn entries(&self) -> Box<dyn Iterator<Item = (&String, &FunctionSummary)> + '_> {
        (**self).entries()
    }
}

/// Two summary lookups read as one: `first` answers a name it holds, and
/// `then` answers the rest. The borrowed form of cloning `then` and
/// extending it with `first`.
pub struct SummaryOverlay<'a, A: ?Sized, B: ?Sized> {
    /// Answers every name it holds.
    pub first: &'a A,
    /// Answers the names `first` does not.
    pub then: &'a B,
}

impl<A: SummaryLookup + ?Sized, B: SummaryLookup + ?Sized> SummaryLookup
    for SummaryOverlay<'_, A, B>
{
    fn get(&self, name: &str) -> Option<&FunctionSummary> {
        self.first.get(name).or_else(|| self.then.get(name))
    }

    fn is_empty(&self) -> bool {
        self.first.is_empty() && self.then.is_empty()
    }

    fn entries(&self) -> Box<dyn Iterator<Item = (&String, &FunctionSummary)> + '_> {
        Box::new(
            self.first.entries().chain(
                self.then
                    .entries()
                    .filter(|(name, _)| !self.first.contains_key(name)),
            ),
        )
    }
}
