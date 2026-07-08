Juliet Benchmark History
=========================

This page is the detailed, round-by-round engineering history behind SqC's
Juliet Test Suite results: every FP-reduction round, per-CWE tier breakdowns,
the Round 1 baseline table, competitor comparisons, and the full version
history. It exists so the granular "why did this number change" narrative has
a home without bloating the top-level ``JULIET_RESULTS.md``, which tracks only
current state.

See ``JULIET_RESULTS.md`` (repo root) for the current run's numbers, and
:doc:`testing-methodology` for how the benchmark itself works (ground truth
classification, manifests, metrics).

Benchmark Environment
----------------------

Runtime varies significantly by machine and parallelism. Historical runs below
were captured on a mix of hardware; always record machine/job count when
reporting new results.

.. list-table::
   :header-rows: 1
   :widths: 30 18 8 8 14 30

   * - Run
     - Machine
     - Cores
     - Jobs
     - Total Runtime
     - Notes
   * - v0.2.1 – v0.2.25 (full suite)
     - 24-core workstation
     - 24
     - 12
     - ~40–50 min
     - MCP benchmark server, full 118 CWE suite
   * - v0.3.8 – v0.3.9 (12-CWE subset)
     - 4-core laptop
     - 4
     - 4
     - TBD
     - ``run_juliet_multi_cwe.sh``, 12-CWE subset only

The parallel runner (``run_juliet_parallel.sh``) defaults to ``JOBS=12``.
Higher core counts reduce wall-clock time but don't affect per-CWE results.
When comparing runtimes across versions, ensure the same machine and job count
were used.

FP Reduction History (Full Round List)
----------------------------------------

Every tracked round from the original baseline through the last full-suite
run (v0.3.17). ``testing-methodology.rst`` carries a condensed milestone
version of this table; this is the complete list.

.. list-table::
   :header-rows: 1
   :widths: 10 8 42 10 10 8 8

   * - Round
     - Version
     - Fixes
     - TP
     - FP
     - TP Rate
     - FP Delta
   * - Baseline
     - v0.2.1
     - --
     - 586,539
     - 839,341
     - 41.1%
     - --
   * - Round 1
     -
     - INT08-C, CON08-C, DCL20-C, ARR38-C
     - 552,645
     - 752,422
     - 42.3%
     - -86,919
   * - Round 2
     -
     - EXP33-C, SIG31-C, ARR01-C, DCL30-C, DCL02-C
     - 555,700
     - 736,563
     - 43.0%
     - -15,859
   * - Round 3
     -
     - DCL31-C, DCL07-C, FLP34-C
     - 402,013
     - 537,589
     - 42.8%
     - -198,974
   * - Round 4
     -
     - EXP12-C, FLP03-C, INT32-C
     - 363,914
     - 492,648
     - 42.5%
     - -44,941
   * - Round 5
     -
     - FLP02-C, DCL06-C, INT30-C
     - 340,894
     - 475,813
     - 41.7%
     - -16,835
   * - Round 6
     -
     - Cross-file analysis (``-d``)
     - 247,757
     - 327,191
     - 43.1%
     - -148,622
   * - Round 7
     -
     - EXP36-C, EXP34-C, ARR37-C
     - 231,053
     - 301,475
     - 43.4%
     - -25,716
   * - Round 8
     -
     - DCL40-C, FLP32-C, ERR33-C
     - 230,992
     - 296,415
     - 43.8%
     - -5,060
   * - Round 9
     -
     - CFG, data-flow, inter-procedural
     - 230,643
     - 296,342
     - 43.8%
     - -73
   * - Round 11
     -
     - DCL07-C/DCL31-C: ALL_CAPS + POSIX std_functions
     - 207,800
     - 272,782
     - 43.2%
     - -23,560
   * - Round 12
     - v0.2.4
     - INT07-C, INT32-C, EXP10-C, EXP34-C, INT30-C, MEM10-C, STR31-C, Windows API
     - 189,950
     - 243,849
     - 43.8%
     - -28,933
   * - Round 13
     -
     - STR31-C: L-prefix + literal-source suppression
     - 189,016
     - 239,724
     - 44.1%
     - -4,125
   * - Round 15
     -
     - EXP34-C: if/else branch merge (variant 12) — measured by MCP server, not directly comparable to legacy runner counts above
     - n/a
     - n/a
     - 44.7%
     - n/a
   * - Round 16
     - v0.2.6
     - DCL13-C main() + MEM10-C param-only null check — same MCP-server caveat as Round 15
     - n/a
     - n/a
     - 44.8%
     - n/a
   * - --
     - v0.2.7
     - INT36-C TP restore + INT31-C FP fix
     - 172,780
     - 215,671
     - 44.5%
     - -1
   * - --
     - v0.2.11
     - INT32-C bounds-check detection, INT30-C macro fixes
     - 172,780
     - 215,669
     - 44.5%
     - -2
   * - --
     - v0.2.12
     - DCL13-C pointer modification + INT01-C sizeof skip
     - 169,161
     - 210,138
     - 44.6%
     - -5,531
   * - --
     - v0.2.13
     - INT31-C implicit narrowing + real-world FP fixes
     - 158,403
     - 196,177
     - 44.7%
     - -13,961
   * - --
     - v0.2.15
     - Real-world FP cleanup (17 patterns)
     - 146,714
     - 185,499
     - 44.2%
     - -10,678
   * - --
     - v0.2.16
     - EXP34-C: call-site null propagation (Phase 2)
     - 146,733
     - 185,510
     - 44.2%
     - +11
   * - --
     - v0.2.17
     - Phase 3: MEM10-C, API00-C, API02-C, prescan enhancement
     - 146,913
     - 185,591
     - 44.2%
     - +81
   * - --
     - v0.2.18
     - INT31-C pointer cast, ARR36-C type filter, API00-C void-cast, INT30-C guards
     - 145,639
     - 184,645
     - 44.1%
     - -946
   * - --
     - v0.2.19
     - INT30-C loop guards, prescan null guards, ARR00-C crash fix
     - 145,639
     - 184,644
     - 44.1%
     - -1
   * - --
     - v0.2.20
     - API00-C static skip, INT01-C dedup, EXP37-C init_declarator, EXP34-C array NotNull
     - 144,278
     - 181,924
     - 44.2%
     - -2,720
   * - --
     - v0.2.21
     - const_eval value-range analysis + real-world Round 6 FP fixes
     - 137,921
     - 175,667
     - 44.0%
     - -6,257
   * - --
     - v0.2.22
     - INT30-C: extend upper-bound guard to if_statement
     - 137,921
     - 175,673
     - 44.0%
     - +6
   * - --
     - v0.2.23
     - INT32-C const_eval alloc/memory/abs + INT30-C uint64_t + built-in macros
     - 131,661
     - 163,585
     - 44.6%
     - -12,088
   * - --
     - v0.2.25
     - ARR32-C tightening, INT18-C/EXP05-C removal, value-range FP fixes
     - 130,199
     - 161,965
     - 44.6%
     - -1,620
   * - --
     - v0.3.5
     - Struct field type resolution, DCL13-C/DCL30-C/EXP33-C FP fixes
     - 130,004
     - 161,510
     - 44.6%
     - -455
   * - --
     - v0.3.8
     - STR31-C, API00-C, EXP34-C, EXP33-C FP fixes — 12-CWE subset (~25K files), not full suite: TP=61,799 FP=77,826
     - n/a
     - n/a
     - 44.3%
     - n/a
   * - --
     - v0.3.9
     - DCL08-C, EXP36-C, INT36-C, INT01-C, EXP33-C FP fixes — same 12-CWE subset: TP=61,349 FP=77,245 (-450 TP / -581 FP vs v0.3.8)
     - n/a
     - n/a
     - 44.3%
     - n/a
   * - --
     - v0.3.14
     - EXP33-C for-loop init, INT30-C subtraction guard, EXP34-C param null propagation — full suite resumes here
     - 126,106
     - 158,036
     - 44.4%
     - -3,474
   * - --
     - v0.3.17
     - CWE-78 macro alias resolution + CWE-253 incorrect-return check
     - 128,038
     - 160,496
     - 44.4%
     - --

**Trend**: Diminishing returns on FP reduction via rule tuning — Round 3
removed 199K FP; by Round 8 only 5K. Cumulative FP reduction from baseline
through v0.3.17: -678,845 (-80.9%).

Per-Round Fix Details
-----------------------

v0.3.19 — Fast Benchmark Mode + CWE-78 Taint Tracking
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

First benchmark using **fast mode** (``--fast``): per-CWE manifests that
include only CWE-matched rules, eliminating noise from unrelated rules. 68
CWEs scanned (29 skipped — no CWE-mapped rules), 12 parallel jobs.

Fast benchmark mode: ``generate_rule_cwe_map.py`` generates 147 per-CWE TOML
manifests. ``run_juliet_parallel.sh --fast`` uses them. Noise ratio drops to
0% by design.

**ENV03-C function-scoped sanitization**: ``clearenv()``/``setenv("PATH")``
now checked per-function instead of file-level. A ``clearenv()`` in one
function no longer suppresses violations in other functions in the same file.

**STR02-C intra-function taint tracking**: Replaced blanket
"non-literal = risky" check with taint analysis. Tracks ``recv()``,
``fgets()``, ``fgetws()``, ``scanf()``, ``getenv()``, etc. as taint sources.
Handles cast expressions like ``(char *)(data + offset)``. Function
parameters treated as tainted by default. Taint propagation through
``strcpy``/``sprintf``/``memcpy``.

CWE-78 impact (v0.3.17 → v0.3.19, fast mode):

.. list-table::
   :header-rows: 1
   :widths: 20 12 12 20

   * - Metric
     - v0.3.17
     - v0.3.19
     - Delta
   * - CWE-78 TP
     - 1,282
     - 1,204
     - -78
   * - CWE-78 FP
     - 1,773
     - 1,443
     - -330
   * - CWE-78 Precision
     - 42.0%
     - 45.5%
     - +3.5pp
   * - CWE-78 Per-file
     - 13.0%
     - 13.0%
     - --
   * - STR02-C TP
     - ~278
     - 200
     - -78 (cross-function)
   * - STR02-C FP
     - ~382
     - 52
     - -330 (-86%)

CWE-aware highlights (fast mode, CWE-matched rules only):

=====  ===============  ===============  =========  ========  =========================
CWE    CWE-matched TP   CWE-matched FP   Precision  Per-file  Notes
=====  ===============  ===============  =========  ========  =========================
252    179              0                100%       16.5%     ERR33-C
253    178              0                100%       26.0%     ERR33-C
690    290              62               82.4%      25.9%     EXP34-C
197    259              126              67.5%      37.4%     INT31-C
401    284              287              49.7%      21.7%     MEM31-C
78     1,204            1,443            45.5%      13.0%     ENV03-C/STR02-C taint
476    140              161              46.5%      29.0%     EXP34-C
190    650              820              44.2%      12.9%     INT30-C/INT32-C
194    447              626              41.7%      27.0%     INT31-C (new in v0.3.18)
195    406              588              40.8%      24.8%     INT31-C (new in v0.3.18)
121    854              1,317            39.3%      12.8%     STR31-C/ARR30-C
=====  ===============  ===============  =========  ========  =========================

**Perfect precision (100% TP)**: CWE-244, CWE-252, CWE-253, CWE-338, CWE-467,
CWE-481, CWE-587, CWE-590, CWE-591, CWE-681 (10 CWEs).

**Zero-detection CWEs** (rules mapped but 0 violations): CWE-114, CWE-188,
CWE-226, CWE-259, CWE-272, CWE-273, CWE-327, CWE-367, CWE-459, CWE-464,
CWE-468, CWE-469, CWE-666, CWE-672, CWE-676, CWE-761, CWE-762, CWE-789,
CWE-843 (19 CWEs).

**Duration**: ~8 min wall time (12 jobs, 4-core laptop), 68 CWEs scanned.
Fast mode is ~10x faster than full suite for CWE-focused analysis.

v0.3.17 — CWE-78 Macro Alias Resolution + CWE-253 Incorrect Return Check
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Two new detection capabilities: P6 (CWE-78 macro alias resolution) and P7
(CWE-253 incorrect comparison validation).

**P6: CWE-78 macro alias resolution** (commit ``d8587d80``): Added
``collect_macro_aliases()`` to resolve ``#define SYSTEM system`` patterns.
ENV33-C, ENV03-C, STR02-C now detect dangerous function calls through macro
indirection. Also added Windows exec/spawn variants (``_execl``, ``_execv``,
``_spawnl``, etc.) to ENV33-C and STR02-C.

**P7: CWE-253 ERR33-C comparison validation** (commit ``83a71e54``): Functions
classified by error return kind (NullPointer, NegativeInt, Eof, NonZero,
Count). When a direct call appears in a binary_expression, the comparison
operator/value is validated against function semantics. Detects:
``fgets() < 0`` (pointer with ordered op), ``fprintf() == 0`` (error is < 0),
``putc() == 0`` (error is EOF), ``remove() == 0`` (0 = success),
``fwrite() < 0`` (size_t unsigned). Includes wchar_t variants and macro alias
resolution.

Juliet impact (v0.3.14 → v0.3.17): Overall TP 126,106→128,038 (+1,932), FP
158,036→160,496 (+2,460), TP rate 44.4% → 44.4% (unchanged) — net increase
from new detections (macro-resolved calls + CWE-253 patterns).

CWE-aware highlights (first run with CWE-aware scoring):

=====  ===============  ===============  =========  ========  ================================
CWE    CWE-matched TP   CWE-matched FP   Precision  Per-file  Notes
=====  ===============  ===============  =========  ========  ================================
253    178              0                100%       26.0%     New — P7 detection
252    179              0                100%       16.5%     Existing ERR33-C
690    290              62               82.4%      25.9%     EXP34-C null deref from return
78     1,282            1,773            42.0%      13.0%     P6 macro aliases
590    94               0                100%       10.4%     MEM31-C free-not-on-heap
467    20               0                100%       37.0%     ARR01-C sizeof-on-pointer
481    12               0                100%       66.7%     EXP45-C assign-vs-compare
391    36               22               62.1%      37.0%     ERR33-C unchecked error
=====  ===============  ===============  =========  ========  ================================

**CWE-aware aggregate** (68 CWEs with mapped rules): CWE-matched TP rate
44.3%, per-file detection 12.6%, flaw-hit rate 4.6%, noise ratio 93.3%.

**Duration**: 1h 47m 15s (54,484 files, 118 CWEs), 24-core workstation via MCP
benchmark server.

v0.3.14 — EXP33-C, INT30-C, EXP34-C FP Fixes (Full Suite)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

First full-suite benchmark since v0.3.5 (v0.3.8 and v0.3.9 used a 12-CWE
subset only). Includes all changes from v0.3.6–v0.3.14, of which v0.3.8 and
v0.3.9 are documented below.

Additional fixes in v0.3.10–v0.3.14:

- **EXP34-C**: Parameter null propagation — seed callee params with null
  state inferred from call-site arguments.
- **INT30-C**: Subtraction guard — detect ``a - b`` patterns where a
  preceding comparison proves ``a >= b`` and suppress the unsigned wrap
  violation.
- **EXP33-C**: For-loop init recognized as dominating assignment —
  ``for (int i = 0; ...)`` loop variable initializer now counted as
  initialization before first use. Also fixed a double-push in
  ``collect_init_func_calls_for_var`` that caused position deduplication
  failures.

Juliet impact (v0.3.5 → v0.3.14): Overall TP 130,004→126,106 (-3,898), FP
161,510→158,036 (-3,474), TP rate 44.6% → 44.4% (-0.2pp). CWE categories with
data: 106→103. Categories >50% TP: 19→17. v0.3.8/v0.3.9 12-CWE subset had
reported 44.3%; full-suite is 44.4% — consistent with subset measurement.

Top CWEs by FP count (v0.3.14 full suite):

============================================  ======  ======  ====
CWE                                           TP      FP      TP%
============================================  ======  ======  ====
CWE78 OS Command Injection                    17,350  5,592   75.6%
CWE197 Numeric Truncation Error               1,148   227     83.5%
CWE506 Embedded Malicious Code                666     120     84.7%
CWE617 Reachable Assertion                    312     48      86.7%
CWE464 Addition of Data Structure Sentinel    48      5       90.6%
CWE457 Use of Uninitialized Variable          704     2,549   21.6% (worst)
CWE563 Unused Variable                        54      250     17.8%
CWE366 Race Condition Within Thread           1       12      7.7%
============================================  ======  ======  ====

**Duration**: 1h 14m 1s (54,484 files, 118 CWEs), 24-core workstation via MCP
benchmark server.

v0.3.9 — P3214 Real-World FP Fixes (12-CWE Subset)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Targeted at 5 high-frequency FP patterns from P3214 embedded firmware
(CMS80F752x/8051 MCU). 12-CWE subset: TP=61,349, FP=77,245, rate=44.3%
(-450 TP / -581 FP vs v0.3.8).

- **DCL08-C**: Skip pair-offset "relationship" check when all 3+ enumerators
  have explicit values. Protocol/wire-format/register enums assign all values
  deliberately — no implicit relationship to encode. 2-member enums
  (canonical ``{IN_STR_LEN=18, OUT_STR_LEN=20}``) still checked. Eliminates
  ~205 FPs per protocol-heavy file.
- **EXP36-C**: Added ``uint8_t *`` and ``int8_t *`` to alignment map with
  value 1. Previously ``ends_with("*")`` fallback assigned them alignment 4,
  causing ``(uint8_t *)&struct_var`` to be flagged as increasing alignment
  strictness (it decreases it). Eliminates 4 FPs per memcpy/memset site.
- **INT36-C**: Guard ``check_pointer_to_integer_cast`` with
  ``!is_pointer_type(type_text)``. ``is_integer_type("uint8_t *")`` returned
  true because "uint8_t" contains "int". Pointer casts like
  ``(uint8_t *)&x`` were incorrectly flagged as pointer-to-integer
  conversions. Eliminates 14 FPs per file.
- **INT01-C**: Skip ``check_param_list`` when param uses
  ``uint8_t``/``uint16_t``/``int8_t``/``int16_t``. On 8/16-bit MCUs these are
  correct types for size parameters; ``size_t`` would waste scarce registers.
  Eliminates 12 FPs.
- **EXP33-C**: When a variable is initialized in 2+ distinct conditional
  branches (if/else-if without final else), use ``ConditionallyInitialized``
  instead of ``Uninitialized``. Multi-branch chains indicate the programmer
  covers all cases (e.g., exhaustive enum dispatch); sqc cannot prove this
  statically. Single-branch if-without-else still flags. Also fixed position
  deduplication in ``collect_init_func_calls_for_var`` (identifier args were
  pushed twice). Eliminates 31 FPs.

Juliet impact (v0.3.8 → v0.3.9): TP 61,799→61,349 (-450), FP 77,826→77,245
(-581), rate 44.3%→44.3%. TP loss primarily from DCL08-C no longer flagging
all-explicit-value enums (low-confidence detections on protocol enum
patterns).

v0.3.8 — STR31-C, API00-C, EXP34-C, EXP33-C FP Fixes (12-CWE Subset)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Scope: 12-CWE subset (25,860 files); not comparable to the full-suite counts
in the round table above (see the v0.3.8/v0.3.9 rows there for the subset
numbers).

- **STR31-C**: Gate literal-source suppression in ``check_strcpy_safety`` and
  ``check_strcat_safety`` on ``!is_function_parameter(dest)``. Recovers TPs in
  CWE124/127 (not in this 12-CWE set, so no measurable change here).
- **API00-C**: 4 new validation patterns recognized: return-statement null
  check, if/else chain, helper-fn early-return, unsigned char arithmetic
  exclusion. Reduces FPs in real-world code.
- **EXP34-C**: Compound null guard fix — ``parse_all_null_conditions``
  collects ALL variables from ``||`` conditions.
  ``if (a == NULL || b == NULL) return;`` now marks both ``a`` and ``b``
  NotNull on the false branch.
- **EXP33-C**: Field/subscript write on uninitialized struct no longer
  treated as a read (``myUnion.field = x``, ``arr[i].field = x`` don't read
  the base variable); ``process_assignment`` now marks the base variable as
  Initialized on any field write (stack structs and malloc arrays).

EXP33-C delta: TP 2,524→2,225 (-299), FP 3,022→2,446 (-576). FP rate
54.5%→52.4%. Overall: TP 62,098→61,799 (-299), FP 78,402→77,826 (-576), TP
rate 44.2%→44.3% (+0.1pp).

v0.3.5 — Struct Field Type Resolution, Real-World FP Fixes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Struct field type resolution for INT32-C/INT30-C, plus DCL13-C/DCL30-C/
EXP33-C targeted FP fixes.

**Struct field type resolution**: Prescan now collects struct definitions
into ``struct_field_types: HashMap<String, HashMap<String, String>>``.
INT32-C and INT30-C ``infer_type()`` resolves ``field_expression`` nodes
(e.g., ``s->count``) via two-level lookup: variable type → struct name →
field type. Previously returned ``not_applicable``/``unknown`` for all struct
field accesses.

**Real-world FP fixes**: DCL13-C (removed FILE-modifying functions from
READ_ONLY_FUNCTIONS), DCL30-C (added ``conditional_expression`` handling to
``is_alloc_expression()``), EXP33-C (array output parameter recognition for
unknown functions). Cleared 3 inline suppressions.

Juliet impact (0.2.25 → 0.3.5): Overall TP 130,199→130,004 (-195), FP
161,965→161,510 (-455), TP rate 44.6% → 44.6% (unchanged). Minimal Juliet
impact expected — Juliet uses explicit local variables, not struct member
access patterns; real-world impact expected on struct-heavy codebases (curl,
mosquitto, etc.).

Files changed: ``prescan.rs``, ``context.rs``, ``ast_utils.rs``,
``int32_c.rs``, ``int30_c.rs``, ``dcl13_c.rs``, ``dcl30_c.rs``,
``exp33_c.rs``.

v0.2.25 — ARR32-C Tightening, Rule Removals, Value-Range FP Fixes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Mixed release: ARR32-C refinement (pre-existing), INT18-C/EXP05-C rule
removal, and real-world value-range FP fixes.

**ARR32-C tightening** (dominant effect): Refined array size validation to
reduce false positives. -1,201 TP/-926 FP — trades some TPs for cleaner
results. Largest CWE impacts: CWE190 -584 FP, CWE191 -391 FP, CWE194 -148 TP
(no FP change), CWE195 -132 TP (no FP change).

**INT18-C removal**: Rule removed entirely (-232 TP/-621 FP). Was generating
2.7:1 FP:TP ratio — not worth keeping.

**EXP05-C removal**: Rule removed entirely (-3 TP/-12 FP). Negligible
detection with poor ratio.

**INT30-C pointer type detection**: Fixed ``infer_type()`` to check for
pointer types (``*``) before ``is_unsigned_type()``. ``unsigned char *`` was
incorrectly classified as "unsigned" instead of "not_applicable". Also fixed
``extract_type_and_name()`` to include ``*`` in type_map for pointer
declarators, and pointer_expression dereference to strip one ``*`` level.
(-26 TP/-62 FP)

**INT32-C field_expression skip**: ``check_memory_function_overflow()`` now
skips ``field_expression`` nodes (e.g., ``server_host->h_length``) —
``contains_arithmetic()`` was matching ``->`` as subtraction.

**INT32-C/INT30-C small increment suppression**: New
``is_small_increment_of_opaque()`` suppresses ``call_expression + small_literal``
and ``call_initialized_var + small_literal`` patterns where const_eval can't
evaluate function return values.

**INT34-C const_eval integration**: Converted from unit struct to stateful
struct with ``MacroConstantMap``. Shift amount range evaluation via
``try_evaluate_range()`` + loop-bounds validation as fallback.

Juliet impact (0.2.23 → 0.2.25): Overall TP 131,661→130,199 (-1,462), FP
163,585→161,965 (-1,620), TP rate 44.6% → 44.6% (unchanged). Per-rule:
ARR32-C -1,201 TP/-926 FP, INT18-C -232 TP/-621 FP, INT30-C -26 TP/-62 FP,
EXP05-C -3 TP/-12 FP. Only regression: FIO05-C +1 FP (noise), CWE773 +2 FP
(noise). CWE194 -148 TP/0 FP and CWE195 -132 TP/0 FP from ARR32-C changes (TP
loss, no FP benefit).

**Real-world impact**: 7 target FPs eliminated (64 → 61 violations). All from
value-range fixes (INT30-C pointer type, INT32-C field_expr/small_increment,
INT30-C small_increment, INT34-C const_eval).

Files changed: ``int30_c.rs``, ``int32_c.rs``, ``int34_c.rs``, ``mod.rs``,
``arr32_c.rs``, ``exp05_c.rs``, ``int18_c.rs``, ``str04_c.rs``.

v0.2.23 — INT32-C Const-Eval for Allocation/Memory/Abs + INT30-C Built-in Macros
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Major const_eval enhancement: built-in C standard limit macros, sizeof
resolution, and AST-based allocation overflow checks.

**Built-in limit macros**: Added ~35 C standard macros (INT_MAX, UINT_MAX,
CHAR_MAX, etc.) as defaults in ``collect_macro_constants()``. Since
tree-sitter doesn't process ``#include <limits.h>``, const_eval previously
couldn't resolve expressions involving these macros. Now
``INT_MAX/2 + INT_MAX/2``, ``UINT_MAX - 50``, and similar are correctly
evaluated.

**sizeof resolution**: Maps ~20 C types to LP64 sizes (``char``→1,
``int``→4, ``long``→8, ``size_t``→8, pointers→8). Enables const-folding of
``N * sizeof(T)`` allocation expressions.

**INT32-C allocation overflow**: Refactored ``check_allocation_overflow()``
and ``check_memory_function_overflow()`` from text-level
``contains_arithmetic()`` (just ``expr.contains('*')``) to AST node traversal
with ``expression_fits_in_signed()`` (64-bit width for size_t).
``malloc(100 * sizeof(char))`` now resolves to 400 and is suppressed.

**INT32-C abs() suppression**: Two new checks in ``check_abs_overflow()``:
widening cast (``abs((long)data)`` can't overflow because long range
contains all int values) and comparison condition (``if (abs(x) <= limit)``
— the abs() IS the bounds check, not a violation).

**INT30-C uint64_t subtraction skip**: ``uint64_t`` subtraction wrapping is
practically impossible (2^64 ns = ~584 years). Skip unsigned subtraction
checks when both operands are 64-bit.

Juliet impact (0.2.22 → 0.2.23): Overall TP 137,921→131,661 (-6,260), FP
175,673→163,585 (-12,088), TP rate 44.0% → 44.6% (+0.6pp). Per-rule: INT32-C
-2,394 TP/-5,238 FP (2.2:1 ratio), INT30-C -3,866 TP/-6,848 FP (1.8:1 ratio).
Zero rule regressions; only CWE194 +28 FP and CWE195 +25 FP (noise from
const_eval enabling new evaluations). Top CWE improvements: CWE197 +14.8pp TP
rate (69.4%→84.2%), CWE590 +3.1pp, CWE226 +3.5pp, CWE122 -2,809 FP.

Files changed: ``const_eval.rs``, ``int32_c.rs``, ``int30_c.rs``,
``function_summary.rs``.

v0.2.16 — EXP34-C: Call-Site Null Propagation (Phase 2)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Two complementary mechanisms for cross-file null pointer analysis:

**A. Call-site flagging (new TPs)**: Re-enabled ``check_callsite_null_args``
— flags DefinitelyNull arguments passed to callees that don't null-check
them. Removed the old ``dereferences_params`` gate (too aggressive, killed
all TPs). Added ``is_null_safe_function()`` guard for ``free``,
``printLine``, etc. Only fires when callee has a prescan summary (guards
against unknown library functions).

**B. Callee param seeding (FP reduction)**: Prescan second pass collects
argument null states at every call site via AST-level inference
(``infer_arg_null_state``). Aggregates per-callee per-param with lattice
join. Seeds callee params with call-site-derived states instead of blanket
PossiblyNull. Header-declared functions get an implicit Unknown caller to
prevent false NotNull seeding.

Juliet impact (0.2.15 → 0.2.16): Net +11 FP (+0.006%), +19 TP, TP rate 44.2%
→ 44.2% (unchanged at 1dp). Only CWE-476 affected: +19 TP / +17 FP (TP rate
35.9% → 36.6%, +0.7pp). EXP34-C in CWE-476: TP 80 → 99 (+19), FP 94 → 111
(+17). Approach A delivered +19 TPs (call-site flagging working as intended
for Juliet variants 51-54). Approach B had limited impact: most good-source
functions pass identifiers (Unknown from prescan AST inference, not
trackable without dataflow), so param seeding couldn't distinguish good vs
bad callers. Relay chains (variants 52-54) correctly produce Unknown →
PossiblyNull (safe fallback). No impact on other CWEs.

Files changed: ``exp34_c.rs``, ``function_summary.rs``, ``prescan.rs``,
``null_state.rs``.

v0.2.21 — Const-Eval Value-Range Analysis + Real-World Round 6 FP Fixes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

New ``src/analyze/const_eval.rs`` module (~550 lines) implements lightweight
constant evaluation: macro constant collection from ``#define`` nodes,
``ValueRange`` interval arithmetic, recursive AST constant folder, loop-bound
extraction from enclosing ``for``/``while``/``do`` statements, and local
variable range resolution. Integrated into INT32-C and INT30-C as
early-return suppression when
``expression_fits_in_signed()``/``expression_fits_in_unsigned()`` proves
safety.

Additional real-world FP fixes (also included): ARR02-C skip
string-literal-initialized arrays, POS02-C removed ``socket``/``setsockopt``
from privileged operation list, PRE31-C strip string literals before
side-effect analysis, MEM05-C ALL_CAPS macro constant VLA suppression +
word-boundary recursion matching.

Juliet impact (0.2.20 → 0.2.21): Overall TP 144,278→137,921 (-6,357), FP
181,924→175,667 (-6,257), TP rate 44.2% → 44.0% (-0.2pp). Zero CWE/rule
regressions. Top rule changes: INT32-C -2,849 FP/-2,147 TP (const_eval),
POS02-C -1,660 FP/-2,398 TP (socket/setsockopt), MEM05-C -1,454 FP/-1,638 TP
(ALL_CAPS VLA), ARR02-C -157 FP/-88 TP, INT30-C -136 FP/-86 TP. **POS02-C
concern**: 0.69:1 FP:TP ratio — loses more TPs than FPs; Juliet patterns use
``socket()``/``setsockopt()`` in good/bad function pairs, so removing the
check suppresses violations in surrounding code (real-world impact much
smaller, -167 across curl+hostap). CWE190 (Integer Overflow): -1,269 FP
(biggest CWE improvement); CWE191: -848 FP.

**Real-world results**: INT32-C 10→8 (-2 macro×literal FPs suppressed).
INT30-C unchanged.

Files changed: ``const_eval.rs`` (NEW), ``context.rs``, ``prescan.rs``,
``mod.rs``, ``int32_c.rs``, ``int30_c.rs``, ``arr02_c.rs``, ``pos02_c.rs``,
``pre31_c.rs``, ``mem05_c.rs``.

v0.2.20 — Real-World FP Fixes (API00-C, INT01-C, EXP37-C, EXP34-C)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Fixes driven by real-world false positive analysis. Four rounds of targeted
fixes (transitive includes, snprintf arg count, K&R declaration, static
function skip, DCL13-C alias tracking, INT01-C dedup, stack array NotNull).

- **API00-C static function skip**: ``check_function_parameter_validation()``
  returns early for ``static`` functions and ``STATIC`` macro prefixes.
  API00-C is about public API contracts — static functions are internal.
- **INT01-C duplicate firing fix**: ``check_size_params()`` double-visited
  ``function_declarator``/``parameter_list`` nodes via both explicit child
  iteration and general recursion. Fix: skip already-handled node kinds in
  general recursion.
- **EXP37-C init_declarator skip**: K&R-style declaration check now skips
  ``declaration`` nodes with ``init_declarator`` child (variable declarations
  with initialization, not function prototypes).
- **EXP34-C stack array NotNull**: ``collect_assignments_recursive()`` in
  prescan now detects ``array_declarator`` children and marks them NotNull
  (stack arrays can never be null).
- **FIO47-C snprintf arg count**: ``count_arguments()`` subtracts 3 for
  ``snprintf``/``vsnprintf`` (buffer + size + format).
- **DCL13-C address-of-member + alias**: Detects ``&(param->field)`` in
  function args and ``T *local = param;`` alias patterns as modification
  through the parameter.

Juliet impact (0.2.19 → 0.2.20): Overall TP 145,639→144,278 (-1,361), FP
184,644→181,924 (-2,720), TP rate 44.1% → 44.2% (+0.1pp). No CWE
regressions. Top rule changes: API00-C -1,917 FP (static skip), INT01-C -231
FP (dedup), EXP34-C -221 FP (array NotNull), DCL30-C -201 FP, FIO47-C -88 FP.
No rule regressions — previously reported POS02-C/ERR05-C/MEM06-C
"regressions" were a measurement artifact (see the per-rule data accuracy
note below).

Files changed: ``api00_c.rs``, ``int01_c.rs``, ``exp37_c.rs``,
``fio47_c.rs``, ``dcl13_c.rs``, ``prescan.rs``.

v0.2.19 — Real-World FP Reduction (INT30-C Loop Guards, Prescan Null Guards, ARR00-C Fix)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Three changes targeting real-world false positives (not Juliet-specific
patterns).

**INT30-C loop-bounded increment**: Added ``is_add_one_bounded_by_loop()``
and ``is_bounded_by_loop_condition()`` — walk AST ancestors for enclosing
``while``/``for`` with ``var < limit`` condition. Suppresses ``var + 1``,
``var += 1``, ``var++`` when bounded by loop condition (proves no unsigned
wrap).

**Prescan early-return null guards**: Added
``collect_early_return_null_guards()`` to detect ``if (p == NULL) return;``
patterns at function entry. Marks guarded parameters as NotNull in
local_states for downstream rules (EXP34-C, API00-C caller-aware
suppression).

**ARR00-C crash fix**: ``array_size - 1`` panicked when ``array_size`` was 0
(unsigned underflow). Changed to ``saturating_sub(1)``.

Juliet impact (0.2.18 → 0.2.19): Overall TP 145,639→145,639 (0), FP
184,645→184,644 (-1), TP rate 44.1% → 44.1% (unchanged) — essentially
neutral, changes target real-world patterns not present in Juliet. Rule-level
churn: FIO06-C -169 FP (prescan improvement) offset by FIO03-C +169 FP,
ARR00-C -74 FP offset by EXP10-C +74 FP. No CWE-level regressions.

Files changed: ``int30_c.rs``, ``prescan.rs``, ``arr00_c.rs``.

v0.2.18 — Quick Wins FP Reduction (INT31-C, ARR36-C, API00-C, INT30-C)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Four targeted fixes addressing false positives identified from real-world
codebases.

- **INT31-C pointer cast skip**: Added early return when either target or
  source type contains ``*``. Pointer reinterpretation casts like
  ``(uint8_t *)buf`` are not integer value conversions and should not
  trigger INT31-C.
- **ARR36-C type filtering**: Only track pointer/array declarators
  (``pointer_declarator`` or ``array_declarator``) in
  ``process_declaration()``. Scalar variables initialized from array
  subscripts (e.g., ``int a = arr[0]``) are not pointers — their
  subtraction/comparison is integer arithmetic, not pointer arithmetic.
- **API00-C void-cast detection**: Recognize ``(void)param`` casts and
  ``UNUSED(param)`` macros as intentional suppression patterns. Parameters
  explicitly cast to void are acknowledged as unused by design and should
  not trigger API00-C's "validate before use" check.
- **INT30-C guard pattern expansion**: Rewrote ``is_guarded_by_gt_zero()`` to
  walk AST ancestors looking for enclosing ``if``, ``while``, and ``for``
  conditions. Added ``condition_implies_positive()`` with compound condition
  support (handles ``&&``/``||`` via ``contains()``). Recognizes
  ``var > expr`` (any lower bound, not just zero) and ``expr < var`` (with
  ``<<``/``<=`` exclusion). Added ``is_subtract_one_guarded()`` for both
  binary subtraction and compound ``-= 1``.

Juliet impact (0.2.17 → 0.2.18): Overall TP 146,913→145,639 (-1,274), FP
185,591→184,645 (-946), TP rate 44.2% → 44.1% (-0.1pp). INT30-C dominant:
-1,292 TP / -935 FP (guard expansion removes both TPs and FPs). CWE191
(Integer Underflow): -1 TP / -45 FP (clean win). WIN03-C: +16 TP / -102 FP
(unexpected improvement). ARR38-C: 0 TP / -36 FP (clean win). Only 1 trivial
regression: CWE675 +1 FP. INT30-C FP:TP ratio ~0.7:1 (loses more TPs than
FPs — guard patterns are slightly too aggressive).

Files changed: ``int31_c.rs``, ``arr36_c.rs``, ``api00_c.rs``, ``int30_c.rs``.

v0.2.17 — Phase 3: CWE-476 FP Reduction (MEM10-C, API00-C, API02-C, Prescan)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Targeted CWE-476 false positive reduction via rule narrowing and enhanced
inter-procedural analysis.

- **MEM10-C positive guard suppression**: Suppress violations when the
  condition is a positive null guard (``!= NULL`` or bare truthiness) and
  the parameter is only used inside the guarded block. This pattern
  (``if (data != NULL) { use(data); }``) is the prescribed fix per EXP34-C —
  MEM10-C was penalizing correct code.
- **API02-C ``const wchar_t *`` exclusion**: Extended existing
  ``const char *`` skip to wide strings. Wide char pointers follow the same
  null-terminated string convention. Original plan to skip all mutable
  ``char *`` was too aggressive — ``char *`` as destination buffer correctly
  requires a size parameter.
- **API00-C caller-aware suppression**: Converted from unit struct to
  stateful with ``function_summaries``. Added ``set_project_context()`` to
  receive summaries from prescan. Before flagging a pointer parameter,
  checks ``callsite_param_null_states``: if all callers pass NotNull →
  suppress violation.
- **Prescan local variable tracking**: Enhanced
  ``collect_callsite_args_from_tree`` with ``collect_local_var_states()`` —
  scans function bodies for simple assignments (``var = NULL`` →
  DefinitelyNull, ``var = "str"`` → NotNull, ``var = malloc(...)`` →
  PossiblyNull). Resolves identifier arguments via local state lookup
  instead of returning Unknown.
- **Variant 45 global tracking**: Verified working correctly —
  ``badSink()`` flagged (reads DefinitelyNull global), ``goodG2BSink()`` and
  ``goodB2GSink()`` correctly suppressed. No code changes needed.

Juliet impact (0.2.16 → 0.2.17): Overall +180 TP, +81 FP, TP rate 44.2% →
44.2% (unchanged). CWE-476: TP 313→320 (+7), FP 542→512 (-30), TP rate 36.6%
→ 38.5% (+1.9pp). CWE-690: TP 3711→3747 (+36), FP 4474→4411 (-63), TP rate
+0.6pp. Per-rule: MEM10-C -38 FP/0 TP (clean elimination), API00-C -3 FP/0
TP. Side benefits from prescan: FIO03-C -169 FP, ERR05-C -105 FP, FIO20-C
-102 FP. Regressions: EXP34-C +76 FP, FIO06-C +169 FP (enhanced prescan
provides more inter-procedural data to these rules).

Files changed: ``mem10_c.rs``, ``api00_c.rs``, ``api02_c.rs``,
``prescan.rs``, ``mod.rs``.

v0.2.15 — Real-World FP Cleanup (17 Patterns)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Addressed 17 FP patterns (~51 violations) identified from real-world
codebases across two commits. Targeted real-world precision over Juliet
benchmark score.

Commit 1 (``d31a6c3``) — Batch 1 (10 rule fixes, ~36 FPs): FIO46-C
source-order stream tracking (store ``start_byte()``, only flag after
fclose); INT32-C returns ``not_applicable`` for ``field_expression`` nodes;
FLP03-C precise scientific notation regex + per-operand float check in
division; EXP40-C checks parent ``declaration`` for ``const`` type
qualifier; EXP12-C checks ``node.parent()`` — skip when return value is
captured; INT01-C skips ``sizeof(...) * N`` binary expressions in allocation
args; INT10-C ``collect_variable_types()`` + ``operand_has_unsigned_type()``
for struct fields; ARR39-C skips ALL_CAPS-only arithmetic (macro/enum
constants); EXP05-C doesn't recurse into ``function_definition`` nodes for
const scanning; EXP02-C exempts ``NULL_CHECK && FUNCTION_CALL`` guard
pattern.

Commit 2 (``0a45c9f``) — 6 remaining violations: INT32-C (x3) propagate
unsigned type through binary_expression chains; INT10-C (x1) skip
``field_expression`` operands in modulo sign check; EXP05-C (x1) skip
``field_expression`` in const-qualification check; ARR39-C (x1) recursive
``is_all_caps_arithmetic()`` for nested expressions.

Juliet impact (0.2.13 → 0.2.15): Net -10,678 FP (-5.4%), -11,689 TP, TP rate
44.7% → 44.2% (-0.5pp) — decline accepted since fixes are semantically
correct for real-world code. Top rule deltas: EXP12-C -5,477 FP/-7,530 TP
(parent check reduces over-flagging), INT01-C -2,714 FP/-740 TP, INT32-C -181
FP/-1,122 TP. FIO46-C and EXP02-C eliminated entirely (0 detections —
correct, these rules had very low signal).

v0.2.13 — INT31-C Implicit Narrowing + Real-World FP Fixes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **INT31-C**: Implemented ``check_assignment_conversion()`` for implicit
  narrowing detection (``uint8_t tag = (uint16_t)(expr)``). Conservative:
  only flags when both LHS and RHS have known integer types. FP
  suppressions: literal-fits, safe-mask (``& 0xFF``), bounds-checked blocks,
  double-flag prevention. Juliet CWE197 impact: -9 TP / -9 FP (unchanged —
  Juliet uses explicit casts). Real-world: +229 new findings across
  curl/hostap/sqlite/mosquitto.
- **INT32-C**: Skip unsigned operands in binary overflow checks (FP-004).
  -8,390 FP, -7,068 TP.
- **DCL07-C/DCL31-C**: Skip indirect calls (function pointers) + preproc
  -guarded calls (FP-009). -2,529/-2,429 FP.
- **DCL15-C**: Skip functions declared in header files (public API). -663 FP
  (curl).

Net: -13,961 FP (-6.6%), -10,758 TP, TP rate 44.6% → 44.7% (+0.1pp). Zero CWE
regressions. Top CWE improvements: CWE90 (-2,737 FP, +8.2pp), CWE78 (-1,704
FP, +2.7pp). Rule regressions under investigation at the time: ARR00-C (+905
FP), WIN03-C (+233 FP), MEM01-C (+225 FP).

Real-world benchmark (0.2.11 → 0.2.13, 4 codebases):

=========  =======  =======  ===================
Codebase   0.2.11   0.2.13   Delta
=========  =======  =======  ===================
curl       93,576   73,816   -19,760 (-21.1%)
hostap     234,421  206,906  -27,515 (-11.7%)
sqlite     177,983  147,091  -30,892 (-17.4%)
mosquitto  39,177   33,638   -5,539 (-14.1%)
**Total**  545,157  461,451  -83,706 (-15.4%)
=========  =======  =======  ===================

v0.2.12 — DCL13-C Pointer Modification + INT01-C sizeof Skip
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **DCL13-C**: Comprehensive pointer modification detection — tracks
  ``*ptr =``, ``ptr[i] =``, ``ptr->field =``, increment/decrement, and
  function-call mutations. Rule went from 4,713 FP → 486 FP (-4,227 FP,
  -3,163 TP). The large TP drop is expected: many "const-qualify"
  violations in Juliet's bad code were technically correct flags but
  low-signal.
- **INT01-C**: Skip ``sizeof(...)`` expressions in allocation argument
  checks. ``malloc(sizeof(int) * n)`` no longer flags ``sizeof(int)`` as an
  implicit conversion. -988 FP, -1,251 TP.
- **Side effects**: DCL13-C's reduction exposed previously-masked
  violations from other rules: EXP33-C (+1,022 FP), API02-C (+628 FP),
  ERR05-C (+431 FP), EXP12-C (+279 FP). Net still strongly positive.

Net: -5,531 FP (-2.6%), -3,619 TP, TP rate 44.5% → 44.6% (+0.1pp). Only 1 CWE
regressed: CWE773 (+3 FP, 0 TP change).

v0.2.7 — INT36-C TP Restore + INT31-C FP Fix
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **INT36-C**: Re-allowed ``->`` field access in pointer-to-int detection
  (+955 TP, +149 FP — restoring TPs from earlier over-aggressive
  filtering).
- **INT31-C**: Added shift-narrowing detection for
  ``(uint8_t)(value >> N)`` patterns (-138 FP, -9 TP; CWE197 TP rate 71.8% →
  75.7%).

Overall: +72 TP, -1 FP.

Round 16 — DCL13-C main() Exemption + MEM10-C Parameter-Only Null Check
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. **DCL13-C**: ``main()`` parameters defined by C standard — not flagged
   for const-qualification.
2. **MEM10-C**: Inline null-check detection restricted to function
   parameters only. Good functions in CWE-476 add ``if (data != NULL)``
   guards; MEM10-C was penalizing this correct pattern. CWE-476 MEM10-C
   FPs: 134 → 28 (-106).

Round 15 — EXP34-C: if/else Branch Merge
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``collect_null_variables`` now merges state from both if/else branches
(union of ``potentially_null_vars``). Fixes variant 12
(``globalReturnsTrueOrFalse``) where if-branch sets ptr=NULL and else-branch
sets ptr=non-null.

Round 14 — EXP34-C: deref_after_check Pattern
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Fixed ``null_check_positions`` to store ``end_byte`` so derefs inside the
null branch (``if (ptr == NULL) { *ptr; }``) are still flagged. +18 TPs, 0
new FPs.

Round 13 — STR31-C: L-prefix and Literal-Source Fixes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Strip L-prefix before measuring wide string literals (``L"*.*"`` → 3
   chars, not 4).
2. Literal source + unknown dest → safe (suppresses FPs in CWE134 good
   functions).

Net: -4,125 FP (-1.7%), -934 TP, TP rate +0.3pp.

Round 12 — INT07-C, INT32-C, EXP10-C, EXP34-C, INT30-C, MEM10-C, STR31-C, Windows API
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- INT07-C: Removed comparison operators from numeric-use detection.
- INT32-C: ``infer_type()`` returns "not_applicable" for non-integer types.
- EXP10-C: ``is_pure_function()`` whitelist (~50 functions).
- EXP34-C: Gates nullable-function-call taint on ``declared_pointer_vars``.
- INT30-C: Not-applicable guards for pointer arithmetic.
- MEM10-C: Removed ``== 0``/``!= 0`` from null-check detection.
- STR31-C: Short literal suppression (≤3 chars).
- **std_functions**: +~100 Windows API functions. DCL31-C/DCL07-C: 21K/20K
  → 2.5K/2.4K FP.

Net: -28,933 FP (-10.6%), TP rate +0.6pp.

Round 9 — CFG, Data-Flow, Inter-Procedural Analysis
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

CFG construction, reaching definitions, inter-procedural function summaries.
Minimal Juliet impact (-73 FP) — targets multi-file real-world codebases.

Round 8 — DCL40-C, FLP32-C, ERR33-C
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- DCL40-C: Removed 31-char prefix collision check (was O(n²) FPs). FP ~12K
  → ~0, 0 TP loss.
- FLP32-C: Windowed error checking (5 stmts) instead of entire scope.
- ERR33-C: Argument-list detection for nested calls.

Net: -5,060 FP (-1.7%), TP rate +0.4pp.

Round 7 — EXP36-C, EXP34-C, ARR37-C
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- EXP36-C: Only check pointer-to-pointer casts; skip integer casts and
  unknown source types.
- EXP34-C: Removed ``_t`` suffix heuristic; field null propagation now
  conditional on base.
- ARR37-C: Stop flagging Unknown pointers; all pointer params now
  ambiguous.

Net: -25,716 FP (-7.9%), TP rate +0.3pp.

Round 6 — Cross-File Analysis (``-d``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``--directories`` CLI option pre-scans for function definitions. DCL31-C/
DCL07-C eliminated FPs from Juliet helper functions. Net: -148,622 FP
(-31.2%), TP rate +1.4pp.

Round 5 — FLP02-C, DCL06-C, INT30-C
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- FLP02-C: AST-node-kind checks instead of text heuristics.
- DCL06-C: Expanded acceptable literal values to 0–10.
- INT30-C: ``collect_variable_types()`` pattern; removed name heuristics.

Net: -16,835 FP (-3.4%), TP rate -0.7pp (DCL06-C is ~50/50).

Round 4 — EXP12-C, FLP03-C, INT32-C
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- EXP12-C: Removed ~30 side-effect functions from "important return value"
  whitelist.
- FLP03-C: Removed assignment_expression arm.
- INT32-C: ``collect_variable_types()`` HashMap; default "unknown" for
  unmapped variables.

Net: -44,941 FP (-8.4%).

Round 3 — DCL31-C, DCL07-C, FLP34-C
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Shared ``std_functions.rs`` database (~270 functions). -198,974 FP. FLP34-C:
type-aware checking.

Round 2 — EXP33-C, SIG31-C, ARR01-C, DCL30-C, DCL02-C
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Fixed preprocessor-block visibility bug (functions inside ``#ifdef``
invisible). DCL02-C similar-identifier check. -15,859 FP; CWE-457 TP rate
12.2% → 22.6%.

Round 1 — INT08-C, CON08-C, DCL20-C, ARR38-C
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- INT08-C: Removed ``int`` from "narrow type" definition.
- CON08-C: Only flag multiple *atomic* functions without mutex.
- DCL20-C: Only flag declarations/prototypes, not definitions.
- ARR38-C: Removed duplicate strcpy/strcat flagging.

Net: -86,919 FP (-10.4%), TP rate +1.2pp.

Performance by CWE Category (Historical Snapshot)
----------------------------------------------------

.. note::
   These tiers reflect an older full-suite run (pre-fast-mode). See
   ``JULIET_RESULTS.md`` for current per-CWE precision via
   ``python -m bench get-cwe-detail`` / the MCP ``get_cwe_detail`` tool.

Tier 1: Strong Detection (TP > 50%) — 18 categories
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

===  ===================================  =========  ======
CWE  Category                             TP Rate    Files
===  ===================================  =========  ======
464  Data Structure Sentinel Addition     89.1%      56
617  Reachable Assertion                  86.7%      354
506  Embedded Malicious Code              85.7%      158
587  Fixed Address to Pointer             100%       18
526  Info Exposure via Env Variables      100%       18
78   OS Command Injection                 76.1%      5,600
114  Process Control                      73.6%      672
427  Uncontrolled Search Path Element     72.0%      560
510  Trapdoor                             70.0%      70
197  Numeric Truncation Error             84.2%      1,008
15   External Control of System/Config    66.9%      56
620  Unverified Password Change           64.4%      36
194  Unexpected Sign Extension            59.9%      1,344
188  Reliance on Data/Memory Layout       59.5%      36
123  Write-What-Where Condition           58.6%      168
90   LDAP Injection                       57.9%      560
195  Signed-to-Unsigned Conversion        57.9%      1,344
835  Infinite Loop                        50.0%      18
===  ===================================  =========  ======

Tier 2: Moderate Detection (35–50%) — 68 categories
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The bulk of categories (64%) cluster here. Includes buffer overflows
(CWE-121 ~43%, CWE-122 ~42%), format strings (CWE-134 ~37%), and resource
management.

Tier 3: Below Average (25–35%) — 16 categories
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Includes integer overflow/underflow (CWE-190 ~33%, CWE-191 ~35%), memory
management (CWE-401 ~34%, CWE-415 ~34%), NULL pointer dereference (CWE-476
~39%).

Tier 4: Weak Detection (<25%) — 4 categories
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

===  ==============================  =========  ================================
CWE  Category                        TP Rate    Root Cause
===  ==============================  =========  ================================
256  Plaintext Password Storage      ~15%       No credential-storage rules
338  Weak PRNG                       ~23%       No PRNG-quality rules
457  Use of Uninitialized Variable   ~24%       Improved from 12.2% after fixes
319  Cleartext Transmission          ~25%       Limited cleartext detection
===  ==============================  =========  ================================

Full Per-CWE Results (Round 1 Baseline)
------------------------------------------

.. note::
   This table reflects Round 1 (42.3% TP rate). Current performance is much
   higher. Relative ordering remains representative of rule difficulty.

===  ====================================  ======  ======  ======  =========
CWE  Vulnerability Type                    Files   TP      FP      TP Rate
===  ====================================  ======  ======  ======  =========
506  Embedded Malicious Code               158     3,421   552     86.1%
15   External Control of System/Config     56      1,255   422     74.8%
427  Uncontrolled Search Path Element      560     7,656   2,798   73.2%
78   OS Command Injection                  5,600   79,292  30,203  72.4%
617  Reachable Assertion                   354     2,685   1,192   69.3%
197  Numeric Truncation Error              1,008   7,899   3,733   67.9%
123  Write-What-Where Condition            168     2,239   1,213   64.9%
114  Process Control                       672     8,839   4,973   64.0%
194  Unexpected Sign Extension             1,344   18,260  12,440  59.5%
510  Trapdoor                              70      1,450   1,037   58.3%
195  Signed-to-Unsigned Conversion         1,344   16,087  11,865  57.6%
90   LDAP Injection                        560     12,600  10,252  55.1%
464  Data Structure Sentinel Addition      56      334     280     54.4%
526  Info Exposure via Env Variables       18      69      58      54.3%
587  Fixed Address to Pointer              18      36      31      53.7%
680  Integer Overflow to Buffer Overflow   336     5,381   4,715   53.3%
188  Reliance on Data/Memory Layout        36      286     275     51.0%
843  Type Confusion                        100     279     340     45.1%
481  Assigning Instead of Comparing        18      195     239     44.9%
480  Use of Incorrect Operator             18      79      97      44.9%
121  Stack-Based Buffer Overflow           5,906   50,353  66,007  43.3%
122  Heap-Based Buffer Overflow            3,656   42,202  58,891  41.7%
134  Uncontrolled Format String            3,360   52,276  90,251  36.7%
476  NULL Pointer Dereference              372     1,222   2,475   33.1%
190  Integer Overflow                      5,040   26,103  54,636  32.3%
191  Integer Underflow                     3,864   19,849  40,831  32.7%
401  Memory Leak                           1,228   10,976  23,198  32.1%
416  Use After Free                        150     1,787   4,698   27.6%
457  Use of Uninitialized Variable         616     5,045   36,338  12.2%
===  ====================================  ======  ======  ======  =========

**TOTALS (106 categories)**: 54,484 files, TP 552,645, FP 752,422, TP rate
42.3%.

12 categories had no C test data (Java/C++ only): CWE-23, CWE-36, CWE-396,
CWE-397, CWE-440, CWE-500, CWE-561, CWE-562, CWE-672, CWE-674, CWE-676,
CWE-762.

Per-Rule Data Accuracy Note (2026-03-03)
--------------------------------------------

Prior to this date, the analysis script output only the **top 10 rules** per
CWE for TP and FP. The MCP benchmark server aggregated per-rule totals from
these top-10 lists, producing lossy data. This caused:

- **Phantom regressions**: Rules appearing in the top-10 window when other
  rules dropped out (e.g., v0.2.20's reported POS02-C/ERR05-C/MEM06-C
  "regressions" were entirely phantom — zero actual change).
- **Inaccurate per-rule deltas**: Numbers could be undercounted (rule only
  in top-10 for some CWEs) or overcounted (rule entering top-10 due to
  another rule's reduction).
- **Total TP/FP and TP rates were always correct** — these were computed
  from full violation data, not per-rule aggregation.

The analysis script now outputs all rules, and all runs since have been
reanalyzed with full per-rule data. Historical per-rule numbers in the
"Per-Round Fix Details" section above predate this fix and may have varying
accuracy. The overall direction of changes was generally correct.

Competitor Comparison
-------------------------

.. list-table::
   :header-rows: 1
   :widths: 14 10 8 30 10 8 10

   * - Tool
     - Detection Rate
     - FP Rate
     - Analysis Depth
     - Juliet Data
     - CERT C
     - Price
   * - SqC
     - 44.6%
     - 55.4%
     - AST + CFG + inter-procedural + call-site null + local var tracking + const_eval
     - Full (118 CWEs)
     - 283 rules
     - --
   * - Semgrep CE
     - 44–48%
     - Very low
     - AST (tree-sitter)
     - No
     - Community
     - Free
   * - Semgrep Pro
     - 72–75%
     - Very low
     - AST + taint + inter-file
     - No
     - Community
     - Commercial
   * - Infer
     - ~55%
     - ~45%
     - Separation logic
     - Partial (4 CWEs)
     - No
     - Free
   * - Flawfinder
     - ~40%
     - High
     - Lexical scanning
     - Indirect
     - No
     - Free
   * - CodeQL
     - ~29%
     - Moderate
     - Data-flow, taint
     - Indirect
     - Partial
     - Free/Commercial
   * - Cppcheck
     - Low
     - Very low
     - Data-flow
     - Indirect
     - Partial
     - Free
   * - Coverity
     - Best-in-class
     - ~15–20%
     - Inter-procedural, path-sensitive
     - Not public
     - Partial
     - Enterprise
   * - Commercial "Tool C"
     - ~73%
     - ~7%
     - Inter-procedural
     - Yes (22 CWEs)
     - --
     - Commercial

The SqC row above is from the 44.6% full-suite era (v0.2.23); current fast-mode
TP rate is 83.7% (v0.4.84, see ``JULIET_RESULTS.md``) but is not directly
comparable since the competitor figures below were not re-measured
fast-mode/CWE-matched.

"Commercial Tool C" is anonymized from `Goseva-Popstojanova & Perhinschi 2015
<https://community.wvu.edu/~kagoseva/Papers/IST-2015.pdf>`_, tested on 22
CWEs only.

Key context from literature:

- Tools on average find ~20% of weaknesses in basic Juliet test cases
  (`ISSTA 2022 <https://dl.acm.org/doi/10.1145/3533767.3534380>`_).
- Even commercial tools miss 27% of C/C++ vulnerabilities (Goseva 2015).
- FP rates range from 6.5% to 76%+ depending on rule set.
- Industry target for developer adoption is 10–20% FP rate.
- No single tool is comprehensive; academic consensus recommends tool
  combination.

Sources: `ISSTA 2022 <https://dl.acm.org/doi/10.1145/3533767.3534380>`_ |
`Goseva 2015 <https://community.wvu.edu/~kagoseva/Papers/IST-2015.pdf>`_ |
`JKU 2014 <https://www.se.jku.at/wp-content/uploads/2014/08/2014.Using-the-Juliet-Test-Suite.pdf>`_ |
`Semgrep Blog 2025 <https://semgrep.dev/blog/2025/security-research-comparing-semgrep-community-edition-and-semgrep-code-for-static-analysis/>`_

Version History (v0.2.1 – v0.3.17)
--------------------------------------

Full-suite runs only (pre-fast-mode). See ``JULIET_RESULTS.md`` for
fast-mode versions from v0.3.20 onward, or query ``data/benchmarks.db``
directly for every run.

.. list-table::
   :header-rows: 1
   :widths: 14 8 8 8 8 14 40

   * - Version
     - TP Rate
     - FP
     - TP
     - Runtime
     - Machine
     - Notes
   * - v0.2.1 (baseline)
     - 41.1%
     - 839,341
     - ~584K
     - --
     - 24-core workstation
     - Original
   * - v0.2.4
     - 43.8%
     - 243,849
     - 189,950
     - --
     - 24-core workstation
     - Windows API + multiple rule fixes
   * - v0.2.6
     - 44.5%
     - 215,672
     - 172,708
     - --
     - 24-core workstation
     - CFG null state + bounds-check detection
   * - v0.2.7
     - 44.5%
     - 215,671
     - 172,780
     - --
     - 24-core workstation
     - INT36-C TP restore + INT31-C FP fix
   * - v0.2.12
     - 44.6%
     - 210,138
     - 169,161
     - --
     - 24-core workstation
     - DCL13-C pointer modification + INT01-C sizeof skip
   * - v0.2.13
     - 44.7%
     - 196,177
     - 158,403
     - --
     - 24-core workstation
     - INT31-C implicit narrowing + real-world FP fixes
   * - v0.2.15
     - 44.2%
     - 185,499
     - 146,714
     - --
     - 24-core workstation
     - Real-world FP cleanup (17 patterns)
   * - v0.2.16
     - 44.2%
     - 185,510
     - 146,733
     - --
     - 24-core workstation
     - EXP34-C call-site null propagation (Phase 2)
   * - v0.2.17
     - 44.2%
     - 185,591
     - 146,913
     - --
     - 24-core workstation
     - Phase 3: MEM10-C, API00-C, API02-C, prescan (CWE-476 38.5%)
   * - v0.2.18
     - 44.1%
     - 184,645
     - 145,639
     - --
     - 24-core workstation
     - INT31-C pointer cast, ARR36-C, API00-C void-cast, INT30-C guards
   * - v0.2.19
     - 44.1%
     - 184,644
     - 145,639
     - --
     - 24-core workstation
     - INT30-C loop guards, prescan null guards, ARR00-C fix
   * - v0.2.20
     - 44.2%
     - 181,924
     - 144,278
     - --
     - 24-core workstation
     - Real-world FP fixes: API00-C, INT01-C, EXP37-C, EXP34-C
   * - v0.2.21
     - 44.0%
     - 175,667
     - 137,921
     - --
     - 24-core workstation
     - const_eval value-range analysis + real-world Round 6 FP fixes
   * - v0.2.22
     - 44.0%
     - 175,673
     - 137,921
     - --
     - 24-core workstation
     - INT30-C: extend upper-bound guard to if_statement
   * - v0.2.23
     - 44.6%
     - 163,585
     - 131,661
     - --
     - 24-core workstation
     - INT32-C const_eval alloc/memory/abs + INT30-C uint64_t + built-in macros
   * - v0.2.25
     - 44.6%
     - 161,965
     - 130,199
     - --
     - 24-core workstation
     - ARR32-C tightening, INT18-C/EXP05-C removal, value-range FP fixes
   * - v0.3.5
     - 44.6%
     - 161,510
     - 130,004
     - --
     - 24-core workstation
     - Struct field type resolution (INT32-C/INT30-C), DCL13-C/DCL30-C/EXP33-C fixes
   * - v0.3.8
     - 44.3%
     - 77,826
     - 61,799
     - --
     - 4-core laptop
     - STR31-C, API00-C, EXP34-C, EXP33-C fixes — 12-CWE subset, not full suite (see FP Reduction History table above)
   * - v0.3.14
     - 44.4%
     - 158,036
     - 126,106
     - 1h 14m
     - 24-core workstation
     - EXP33-C, INT30-C, EXP34-C FP fixes (full suite)
   * - v0.3.17
     - 44.4%
     - 160,496
     - 128,038
     - 1h 47m
     - 24-core workstation
     - CWE-78 macro alias + CWE-253 incorrect return check

Scripts and Data Locations
------------------------------

::

    bench/                                 Python benchmark module (python -m bench juliet)

    ~/data/benchmarks/juliet-test-suite-c/
      testcases/                           118 CWE categories, 54,484 .c files
      testcasesupport/                     Shared helper functions

    /tmp/juliet_results/                   Per-run output (MCP benchmark server, legacy pre-SQLite)
    data/benchmarks.db                     Canonical store from v0.3.20 onward (SQLite)
