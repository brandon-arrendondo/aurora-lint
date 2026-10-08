Analysis Architecture
=====================

aurora-lint uses a multi-pass analysis architecture:

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
    [Rule Evaluation] --> Enabled rules applied to AST + CFG + context
        |
        v
    [Suppression Filter] --> Hash-based + wildcard (glob/prefix) suppression
        |
        v
    [Export] --> SARIF, JSON

Analysis Modules
----------------

**Tree-sitter parsing** (``src/parser/mod.rs``; orchestration in ``src/analyze/mod.rs``).
  Fast, incremental, error-tolerant C parsing.  Each ``.c`` file is parsed into
  an AST; the orchestrator coordinates prescan, CFG construction, dataflow, and
  per-rule evaluation with optional Rayon parallelism.

**Cross-file pre-scan** (``src/analyze/prescan.rs``, ``context.rs``).
  Walks the ``-d`` directories (or, with no ``-d``, the scan target itself)
  collecting function definitions, header prototypes,
  function summaries, call graphs, macro constants/aliases, struct field types,
  global constants, and global pointer null states.  Second pass aggregates
  call-site argument null states (up to 64 passes, with a warning if they do
  not converge) and propagates transitive frees through parameter
  pass-through chains (to a fixpoint).  Results stored in
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
  reach each program point.  Sole rule consumer: MSC13-C, which reads the
  reaching set directly.  The module also exposes ``is_potentially_freed`` and
  ``is_potentially_null`` for use-after-free and null-dereference queries, but
  no rule calls them today; they are exercised only by the module's own unit
  tests.  (MEM01-C imports just the ``find_node_at_range`` helper from this
  file, not the reaching-definitions analysis.)

**Initialization state** (``src/analyze/init_state.rs``).
  Forward dataflow tracking initialization status with malloc-aware semantics
  (Uninitialized, MaybeUninitialized, Initialized, MallocUninitialized,
  MallocInitialized).  Detects partial-init patterns in loops.  Primary
  consumer: EXP33-C.

**Macro-expansion engine** (``src/analyze/macro_expand.rs``).
  Registry-based, name-independent modeling of function-like macro bodies —
  not a per-macro name allowlist.  ``collect_function_macros`` +
  ``FunctionMacro`` back a growing set of shape predicates regardless of the
  macro's name (as of this writing: output-param writes, the "safe free"
  free+null idiom, generic writes, forwarding to another macro, plain frees,
  clears, and callee-released-parameter detection — see the file's own
  ``pub fn`` list for the current, authoritative set rather than trusting a
  count here). Consumed by |macro_expand_rule_count| rules: |macro_expand_rule_list|.
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
  per-rule lists found by a ruleset-wide duplication sweep.

**Arithmetic-overflow-detection helpers** (``src/utility/cert_c/overflow_helpers.rs``).
  Shared type-map-building and identifier/operand-extraction primitives for
  ``INT30-C``/``INT32-C`` (and one primitive each for ``INT10-C``),
  replacing ~20 identically-named private helpers duplicated across those
  two ~2800-line files — the largest duplicated surface found by that same
  sweep. The overflow-*guard-detection* logic itself
  (``has_overflow_check_*``) stays rule-local: it only looks duplicated:
  ``INT30-C``'s is unsigned-wraparound-focused and ``INT32-C``'s is
  signed-overflow-focused.

**Floating-point type inference** (``src/utility/cert_c/float_typing.rs``).
  Word-boundary-aware float classification of type spellings and literals
  (``is_float_type``, ``is_float_literal``) and the ``collect_variable_types``
  name map, shared by the FLP rule family; and ``expr_is_float``, which types
  an expression by declaration through ``expr_type`` and is the floating
  test of ``INT30-C``, ``INT32-C`` and ``INT33-C``. A follow-up
  migrated 3 of the 9 flagged rules (FLP02-C, FLP34-C, FLP37-C); the other
  6 turned out to check genuinely different concepts (format specifiers,
  ``long double`` specifically, a more comprehensive extended-float set)
  and correctly stay rule-local.

**Internal capability catalog** (``docs/design/internal-capability-catalog.md``).
  A browsable-by-concept catalog of every reusable primitive in
  ``src/utility/cert_c/*.rs`` and ``src/analyze/*.rs`` (macro detection,
  declarator resolution, lvalue/aliasing, constant folding/VRA, CFG,
  function summaries, suppression, cross-file ``ProjectContext``). Skim it
  before writing any new AST/text heuristic in a rule file -- filed after
  a near-duplication of DCL40-C's macro-detection helpers in MSC12-C.

**Suppression system** (``src/analyze/suppression.rs``).
  Inline ``// AURORA-SUPPRESS`` comments and ``suppress.toml`` files (the
  pre-rename ``SQC-SUPPRESS`` / ``.sqc-suppress.toml`` spellings still parse).
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
Reaching definitions                  Iterative worklist dataflow (MSC13-C)
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
                                see above) name-independently recognizes a
                                growing set of shapes for |macro_expand_rule_count|
                                rules; outside those shapes macros are still
                                opaque function
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

**Known departures from the labeling ADRs.** Where detection still
contradicts ADR-0005 (misfires), ADR-0006 (resolve identifiers, not
spelling), ADR-0010 (every compilable configuration counts) or ADR-0011
(what counts as proof), the place is listed in
``docs/design/adr-conformance.md``: the code, the shortcut, and whether a
fix adds or removes findings. A published per-rule figure for a rule with
an open row there carries that caveat.

**No build input is required.** The gaps above are what analyzing source
alone costs, and the tool accepts that cost rather than depending on a
build. A compile database, ``-I``/``-D`` flags and declared environment
facts only refine results. With none of them, each rule takes its strict
reading of the source as found, and gives no credit the source alone can't
prove. ADR-0015 Decision 3
(``docs/adr/0015-default-and-strict-profiles.md``) states the principle and
the tests that keep it true.

Architectural Ceiling
---------------------

At v0.4.116 (a historical figure, not re-measured here), the TP rate was
**83.8%** (Juliet, 74 CWEs; up from 67.5% at v0.3.119). Current figures are
in the README's "How Well Does It Work?" section. By v0.4.116, CWE-190/191
(integer overflow) and CWE-476 (null dereference) had moved substantially
with VRA and null-state work; the remaining gaps were concentrated in a
smaller set of CWEs still requiring deeper analysis:

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

Measured comparisons with clang-tidy, cppcheck, Infer, and Frama-C, with
their dates and tool versions, are in :doc:`tool-comparison`.

**Key context**: on real-world vulnerabilities, even the best single C
analyzer studied misses between 47% and 80%, depending on the evaluation
scenario (Lipp2022); in another study, 27% of C/C++ vulnerabilities were
missed by all three commercial tools tested (Goseva2015). From a developer
survey, Christakis and Bird recommend that analysis designers aim for a
false-positive rate no higher than 15--20%; only 24% of respondents accepted
20% (Christakis2016). See :doc:`bibliography` for full references.
