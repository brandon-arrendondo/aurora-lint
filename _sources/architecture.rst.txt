Analysis Architecture
=====================

SqC uses a multi-pass analysis architecture:

::

    Source Files
        |
        v
    [Tree-sitter Parser] --> AST (per-file)
        |
        v
    [Pre-scan Pass] --> Cross-file context (function defs, summaries, macros,
        |                 struct types, global states, call graph, call-site args)
        v
    [CFG Construction] --> Per-function control-flow graphs
        |
        v
    [Dataflow Analysis] --> Null state, value range, reaching defs, init state
        |
        v
    [Rule Evaluation] --> 307 CERT C rules applied to AST + CFG + context
        |
        v
    [Suppression Filter] --> Hash-based + wildcard (glob/prefix) suppression
        |
        v
    [Export] --> CSV, XLSX, JSON, SARIF

Analysis Modules
----------------

**Tree-sitter parsing** (``src/analyze/mod.rs``).
  Fast, incremental, error-tolerant C parsing.  Each ``.c`` file is parsed into
  an AST; the orchestrator coordinates prescan, CFG construction, dataflow, and
  per-rule evaluation with optional Rayon parallelism.

**Cross-file pre-scan** (``src/analyze/prescan.rs``, ``context.rs``).
  Walks ``-d`` directories collecting function definitions, header prototypes,
  function summaries, call graphs, macro constants/aliases, struct field types,
  global constants, and global pointer null states.  Second pass aggregates
  call-site argument null states and propagates transitive frees through
  parameter pass-through chains (max 8 iterations).  Results stored in
  ``ProjectContext``, optionally cached to binary (``--save-prescan`` /
  ``--load-prescan``).  Consumed by 15+ rules.

**Function summaries** (``src/analyze/function_summary.rs``).
  Lightweight inter-procedural summaries computed during prescan:
  ``frees_params``, ``can_return_null``, ``returns_allocation``,
  ``checks_null_params``, ``modifies_params``, ``dereferences_params``,
  ``never_returns``, ``callsite_param_null_states`` (aggregated from all call
  sites), ``callsite_param_field_null_states`` (struct field propagation),
  ``callsite_param_pointee_null_states`` (pointer-to-pointer propagation),
  ``return_range`` (VRA inter-procedural), ``param_passthroughs`` (transitive
  free tracking).  Consumed by 7 rules.

**Control-flow graphs** (``src/analyze/cfg.rs``).
  Per-function CFG with basic blocks, typed edges (Fallthrough, TrueBranch,
  FalseBranch, BackEdge, Return, Break, Continue, Goto), and
  ``condition_range`` metadata for path-sensitive edge refinement.  Optional
  macro-constant-aware construction for dead-branch elimination.  Consumed by
  8 rules (INT30/31/32/33/34-C, EXP33/34-C, MEM01-C).

**Null state dataflow** (``src/analyze/null_state.rs``).
  Forward dataflow on CFG with NullState lattice (Unknown → DefinitelyNull /
  PossiblyNull / NotNull).  Edge refinement on branch conditions supports
  compound ``||`` / ``&&`` expressions.  Seeded from global pointer states,
  call-site parameter states, and function summaries.  Primary consumer:
  EXP34-C; also used by API00-C.

**Value range analysis** (``src/analyze/value_range.rs``).
  CFG-based forward value-range dataflow for integer variables.  Tracks
  ``TypedRange`` (interval + signedness/bit-width) per variable.  Handles
  sequential assignments, conditional narrowing, loop bounds, and early-return
  guards.  Inter-procedural return ranges from function summaries.  Consumed
  by INT30/31/32/33/34-C.

**Constant evaluation** (``src/analyze/const_eval.rs``).
  Syntactic constant folding of ``#define`` macro constants and arithmetic
  expressions.  Includes built-in C99 ``<limits.h>``/``<stdint.h>`` macros
  (LP64 model).  ``try_evaluate_range()`` computes value ranges from
  constants + variables + loop bounds via ancestor walks.  Consumed by 11
  rules (INT, ENV, ERR, FIO, FLP, STR families).

**Reaching definitions** (``src/analyze/dataflow.rs``).
  Standard iterative worklist algorithm computing which definitions
  (Declaration, Assignment, Parameter, NullAssignment, FreeCall, NullableCall)
  reach each program point.  Supports use-after-free and null dereference
  queries.  Primary consumer: MEM01-C.

**Initialization state** (``src/analyze/init_state.rs``).
  Forward dataflow tracking initialization status with malloc-aware semantics
  (Uninitialized, MaybeUninitialized, Initialized, MallocUninitialized,
  MallocInitialized).  Detects partial-init patterns in loops.  Primary
  consumer: EXP33-C.

**Macro-expansion engine** (``src/analyze/macro_expand.rs``).
  Registry-based, name-independent modeling of function-like macro bodies —
  not a per-macro name allowlist.  ``collect_function_macros`` +
  ``FunctionMacro`` recognize two shapes regardless of the macro's name:
  ``macro_nulls_param_indices`` (the macro frees *and* null-writes its
  argument — the "safe free" idiom, e.g. ``SAFE_FREE``/``mosquitto_FREE``/
  ``Curl_safefree``) and ``macro_output_param_indices`` (the macro writes to
  an output parameter).  Consumed by MEM30-C, MEM31-C, EXP33-C, and DCL31-C.
  Before adding a name-heuristic workaround for a macro-opacity false
  positive, check whether this engine already covers it — see
  ``docs/design/macro-expansion.md`` for the full design rationale and a
  per-rule disposition table.

**Standard function database** (``src/utility/cert_c/std_functions.rs``).
  ~370 C11, POSIX, and Windows API functions recognized to suppress false
  positives on standard library calls (DCL31-C, DCL07-C).

**Call-role classification** (``src/utility/cert_c/call_roles.rs``).
  Single-source-of-truth predicates layered on top of the standard function
  database for "what role does this call play" (``is_allocator_call``,
  ``is_heap_allocator``, ``is_printf_family``, ``is_scanf_family``,
  ``is_sizeof_text``), replacing 7+ independently reinvented, disagreeing
  per-rule lists found by task 481's duplication sweep (task 487).

**Arithmetic-overflow-detection helpers** (``src/utility/cert_c/overflow_helpers.rs``).
  Shared type-map-building and identifier/operand-extraction primitives for
  ``INT30-C``/``INT32-C`` (and one primitive each for ``INT10-C``),
  replacing ~20 identically-named private helpers duplicated across those
  two ~2800-line files — the largest duplicated surface found by task 481's
  sweep (task 490). The overflow-*guard-detection* logic itself
  (``has_overflow_check_*``) stays rule-local: it only looks duplicated:
  ``INT30-C``'s is unsigned-wraparound-focused and ``INT32-C``'s is
  signed-overflow-focused.

**Floating-point type inference** (``src/utility/cert_c/float_typing.rs``).
  Word-boundary-aware float/integer classification (``is_float_type``,
  ``expr_is_float``, ``expr_is_definitely_integer``,
  ``collect_variable_types``) shared by the FLP rule family. Task 491
  migrated 3 of the 9 flagged rules (FLP02-C, FLP34-C, FLP37-C); the other
  6 turned out to check genuinely different concepts (format specifiers,
  ``long double`` specifically, a more comprehensive extended-float set)
  and correctly stay rule-local.

**Internal capability catalog** (``docs/design/internal-capability-catalog.md``).
  A browsable-by-concept catalog of every reusable primitive in
  ``src/utility/cert_c/*.rs`` and ``src/analyze/*.rs`` (macro detection,
  declarator resolution, lvalue/aliasing, constant folding/VRA, CFG,
  function summaries, suppression, cross-file ``ProjectContext``). Skim it
  before writing any new AST/text heuristic in a rule file — filed as task
  479 after a near-duplication of DCL40-C's macro-detection helpers in
  MSC12-C task 475.

**Suppression system** (``src/analyze/suppression.rs``).
  Inline ``// SQC-SUPPRESS`` comments and ``.sqc-suppress.toml`` files.
  SHA-256 hash-based point suppressions and glob/prefix wildcard suppressions.

Current Capabilities
--------------------

====================================  =====================================================
Capability                            Implementation
====================================  =====================================================
Local variable/type inference         Per-function ``collect_variable_types``
Preprocessor block traversal          ``preproc_*`` node recursion
Standard function database            ~370 C11/POSIX/Windows functions
Cross-file function scanning          ``-d`` flag pre-scan with binary cache
CFG construction                      Per-function with ``condition_range`` metadata
Reaching definitions                  Iterative worklist dataflow (MEM01-C)
Inter-procedural summaries            Null returns, freed params, no-return, return
                                      ranges, dereferences, pass-throughs
CFG-based null state dataflow         Forward dataflow with NullState lattice, compound
                                      condition support, global/call-site seeding
Value range analysis                  CFG-based forward dataflow, inter-procedural
                                      return ranges, type-aware intervals
Initialization state analysis         Forward dataflow with malloc-aware semantics
Constant evaluation                   Macro resolution, built-in limits, sizeof types
Macro-expansion engine (registry)     Name-independent free+null and output-param macro
                                      body modeling (MEM30/31-C, EXP33-C, DCL31-C)
Call-site null propagation             Aggregated argument states across all callers
Transitive free propagation           Parameter pass-through chains + field-sensitive
                                      custom-deallocator credit (MEM31-C)
Global pointer null state              Cross-file extern pointer tracking (EXP34-C)
Struct field type resolution           Prescan-collected struct definitions
Taint tracking                        Intra-function (FIO30-C, STR02-C)
Dead-branch elimination               Macro-constant-aware CFG construction
====================================  =====================================================

Known Limitations
-----------------

==============================  ====================================================
Gap                             Impact
==============================  ====================================================
No general macro expansion      Arbitrary macro bodies are not expanded.  A
                                registry-based engine (``macro_expand.rs``,
                                see above) models two recognized shapes
                                (free+null, output-param) name-independently
                                for MEM30/31-C, EXP33-C, DCL31-C; outside
                                those shapes macros are still opaque function
                                calls, partially mitigated by
                                ``collect_macro_aliases`` for constant-valued
                                macros
No alias analysis               Pointer aliasing unresolved; field-scoped alias
                                collection causes cross-function issues
No symbolic execution           Complex path conditions not evaluated
No SSA form                     No use-def chains beyond reaching definitions
VRA intra-procedural only       Inter-procedural argument ranges and field-sensitive
                                VRA not implemented; return ranges available
Limited taint tracking          Intra-function only (STR02-C, FIO30-C);
                                cross-function taint for injection CWEs planned
Struct field tracking limited   Prescan-visible structs only (INT32-C/INT30-C);
                                no field-level free or null tracking
No ownership model              Same-function ownership transfer (allocate + custom
                                deallocator) is credited, but parameter-owned vs.
                                locally-owned struct lifetimes are not distinguished;
                                dominant remaining MEM31-C real-world FP source
==============================  ====================================================

Architectural Ceiling
---------------------

Current TP rate: **83.8%** (Juliet, v0.4.116, 74 CWEs; up from 67.5% at
v0.3.119).  CWE-190/191 (integer overflow) and CWE-476 (null dereference)
have since moved substantially with VRA and null-state work; the remaining
gaps are concentrated in a smaller set of CWEs still requiring deeper
analysis:

- **CWE-190** (integer overflow): 100.0% — resolved via value-range analysis.
- **CWE-191** (integer underflow): 98.5% (was 55.3%) — same VRA work.
- **CWE-476** (null dereference): 67.9% (was 61.9%) vs clang-tidy 94.3%.
  Requires deeper inter-procedural null propagation and alias analysis.
- **CWE-121** (stack buffer overflow): 71.0% (was 57.5%) vs clang-tidy 86.6%.
  Requires symbolic buffer size tracking across assignments.
- **CWE-369** (divide by zero): 57.8% (was 56.0%) vs clang-tidy 94.7%.
  Requires stronger zero-value tracking through assignments; largely
  unmoved despite the VRA/alias investment that lifted 190/191/476/121.

Alias analysis and field-sensitive value tracking remain the two
capabilities most likely to close the remaining gap, particularly for
CWE-369 and the residual CWE-121/476 share tied to pointer aliasing.

Competitor Landscape
--------------------

5-tool comparison on 15 overlapping Juliet CWEs (28,488 files):

==============  ==============  =========  ====================================  ===========
Tool            Detection Rate  FP Rate    Analysis Depth                        Price
==============  ==============  =========  ====================================  ===========
clang-tidy      91.6%           0.8%       AST + path-sensitive                  Free
**SqC**         67.5%           32.5%      AST + CFG + inter-procedural          --
Frama-C         61.0%           39.0%      Abstract interpretation               Free
Infer           43.6%           56.4%      Separation logic                      Free
cppcheck        36.4%           63.6%      Data-flow                             Free
==============  ==============  =========  ====================================  ===========

*SqC row is from the v0.3.119 Juliet benchmark, held fixed here because the
other four tools were not re-run at v0.4.116 — this table is a frozen
snapshot of a one-time comparative study, not a continuously re-measured
figure. SqC's own overall TP rate has since risen to 83.8% (see above); it
is not directly comparable to the 67.5% row without re-running the other
four tools on the same 15-CWE, 28,488-file slice.*

SqC achieved 100% precision (zero FP) on 48 of 74 benchmarked CWEs as of
v0.4.116 (a frozen figure from this study, not re-measured since; see
README.md's Benchmark Highlights for the current 100%-precision-CWE count),
including CWE-690, CWE-761, CWE-78, and CWE-190. Broadest CWE coverage
(74+ CWEs benchmarked vs clang-tidy's 15
in the frozen study above).

**Key context**: Tools on average find ~20% of weaknesses in Juliet
(ISSTA2022). Even commercial tools miss 27% (Goseva2015). Industry FP target
for adoption is 10--20%. See :doc:`bibliography` for full references.
