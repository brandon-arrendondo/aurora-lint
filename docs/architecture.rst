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
    [Rule Evaluation] --> 285 CERT C rules applied to AST + CFG + context
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

**Standard function database** (``src/utility/cert_c/std_functions.rs``).
  ~370 C11, POSIX, and Windows API functions recognized to suppress false
  positives on standard library calls (DCL31-C, DCL07-C).

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
Call-site null propagation             Aggregated argument states across all callers
Transitive free propagation           Parameter pass-through chains (MEM31-C)
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
No preprocessor expansion       Macros appear as function calls; partially mitigated
                                by ``collect_macro_aliases``
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
No ownership model              Cross-function memory ownership untracked;
                                limits MEM31-C/MEM30-C precision
==============================  ====================================================

Architectural Ceiling
---------------------

Current TP rate: **67.5%** (Juliet, v0.3.119, 74 CWEs).  The remaining gaps
are concentrated in CWEs requiring deeper analysis:

- **CWE-190/191** (integer overflow/underflow): 60.9%/55.3% vs clang-tidy 94%.
  Requires more complete value-range propagation and bounds-check recognition.
- **CWE-369** (divide by zero): 56.0% vs clang-tidy 94.7%.
  Requires stronger zero-value tracking through assignments.
- **CWE-476** (null dereference): 61.9% vs clang-tidy 94.3%.
  Requires deeper inter-procedural null propagation and alias analysis.
- **CWE-121** (stack buffer overflow): 57.5% vs clang-tidy 86.6%.
  Requires symbolic buffer size tracking across assignments.

Alias analysis and field-sensitive value tracking are the two capabilities
most likely to lift the ceiling.  Each would require significant
architectural investment but could push TP rate toward 75%+.

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

*SqC results from v0.3.119 Juliet benchmark (74 CWEs). Competitor figures from
prior study on 15 overlapping CWEs.*

SqC achieves 100% precision (zero FP) on 34 CWEs including CWE-690, CWE-761,
CWE-78, and CWE-416.  Broadest CWE coverage (74+ CWEs benchmarked vs
clang-tidy's 15).

**Key context**: Tools on average find ~20% of weaknesses in Juliet
(ISSTA2022). Even commercial tools miss 27% (Goseva2015). Industry FP target
for adoption is 10--20%. See :doc:`bibliography` for full references.
