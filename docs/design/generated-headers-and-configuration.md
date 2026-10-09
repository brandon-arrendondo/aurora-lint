# Build-generated headers describe one configuration

**Status:** design ruled on (2026-10-09), against `5fe0fa57`; §8 records
the decisions and the implementation order. **No engine, rule or CLI code
has changed yet.** Adjudication is not involved: every count below is a
local diagnostic measurement, not a project figure.

**tl;dr.** A build generates some of its headers, and they describe the one
configuration it was run in: declaration lists (seL4's
`structures_gen.h`), function bodies (the inline bitfield accessors in the
same file) and configuration values (`gen_config.h`). Since the benchmark
environment started handing the build's generated-header directories to
the scan (ADR-0018), aurora-lint has read those facts as true for *every*
file and arm it scans, including code that configuration never compiles.
On seL4 that pairing produces findings about constructs that are not there
(DCL31-C, ARR30-C), and withholds findings in code the configuration does
not compile (PRE31-C). One rule fixes all three: **a fact that comes only
from a build-generated header applies to the code that configuration
compiles, and to nothing else.** Elsewhere the scan behaves exactly as it
did when the header was missing. §4 says how a generated header and "the
code that configuration compiles" are recognised without guessing, §5 gives
the rule per effect, §6 what it does to seL4 and what to watch elsewhere.

---

## 1. What was measured

seL4 at its pin, scanned twice with one aurora-lint binary (`e22b0761`):

- **H**: the real-world runner's command with no compile database (the
  corpus's own `include/` and `libsel4/include/` only).
- **P**: the benchmark configuration, i.e. the recipe's compile database
  (built in the benchmark image's tools stage), its include directories ahead
  of the dependency set's (empty for seL4), and `--compile-commands`.

Two control arms isolate the cause. H plus only the database's include
directories, and H plus only `--compile-commands`, both produce findings
byte-identical to P under both presets. The database's `-D` flags and the
empty dependency set contribute nothing; **the whole H→P difference comes
from the generated-header directories becoming searchable.**

| Rule | default | strict | where |
|---|---|---|---|
| DCL31-C | +191 | +191 | 48 in scope, 143 outside |
| ARR30-C | +16 | +16 | 2 in scope, 14 outside |
| PRE31-C | −4 | −131 | strict: 105 in scope, 26 outside |
| INT33-C | −1 | −1 | in scope |

"In scope" is the corpus's `scope_include` minus `scope_exclude`. The build
also declares **which files its configuration compiles**: seL4's only C
translation unit, the generated `kernel_all.c`, concatenates 77 sources,
each marked `#line 1 "<path>"`. Five in-scope files are not among them
(the MCS-only `reply.c`, `schedcontext.c`, `schedcontrol.c`, `sporadic.c`,
and `profiler.c`); every other-architecture file is outside too. Splitting
the delta that way:

| Rule | in a file the configuration compiles | in a file it does not |
|---|---|---|
| DCL31-C | +12 | +179 |
| ARR30-C | +2 | +14 |
| PRE31-C (strict) | −98 | −33 |
| INT33-C | −1 | 0 |

## 2. The three effects, mechanism by mechanism

### 2.1 Declaration lists: DCL31-C

`check_function_call` (`dcl31_c.rs`) reports a direct call to a name that no
scanned or resolved file declares, unless the file *abstains*: its include
closure reaches a project header that could not be found
(`context::unresolved_project_headers_reached`, set in `set_file_path`).
With the generated headers missing, every seL4 file that includes
`structures_gen.h` abstains. With them present, nothing is unresolved, the
abstention never fires, and a call to an accessor that only another
configuration generates (an MCS `call_stack_new`, an ARM
`pde_ptr_get_pdeType`, an x86 VT-x `cap_ept_pml4_cap_new`) is reported as
undeclared.

That claim is false for every configuration that compiles the call: the
build that compiles it generates the declaration. The finding names a
construct that isn't there, which ADR-0005 makes a bug regardless of corpus,
and it exists only by combining one configuration's header with another
configuration's code (ADR-0010 Decision 4).

Two details matter for the fix:

- 179 of the 191 are in files the configuration does not compile at all.
  For those, "the declaration list is incomplete" is exactly the condition the
  existing abstention already encodes. It just doesn't know it holds.
- The other 12 sit in arms of compiled files that the configuration excludes
  (`#ifdef CONFIG_VTX`, an MCS or SMP arm). DCL31-C already suppresses a call
  with any `#if` ancestor in the same file, but that check is syntactic. When
  an arm's braces straddle the `#endif` (a `switch (t) {` opened inside
  `#ifdef CONFIG_VTX`), the parse tree has no `#if` node above the call, and
  the check misses.

### 2.2 Function bodies: PRE31-C

*This corrects the account first given for this effect, which was that the
generated configuration header decides which definition of `printf`/`assert`
is live.* `--report-macro-gaps` shows the engine's definition verdicts for
every macro involved (`printf`, `assert`, `userError`, `IRQT_TO_CORE`,
`IDX_TO_IRQT`, `VTX_TERNARY`, `SMP_COND_STATEMENT`) are identical in H and P.
Macro arms are collected per file and never read another file's `#define`
(`extend_function_macro_arms`, `reachable_arms`).

What changes is callee knowledge. PRE31-C reports a macro argument "with
side effect" when it calls a function the effect analysis cannot show to be
free of side effects; under the strict policy an unproven callee counts
(`call_effect` → `Effect::Unknown`, gated by `pre31_unknown_call_pure`). The
analysis (`side_effects.rs`, `EffectTable`) is transitive and reads every
function body the prescan sees, including static inline bodies from
resolved headers (`fold_header_summaries`). Once `structures_gen.h`
resolves, its 563 inline accessors enter the table. Of the 131 strict
drops, 120 have arguments that call only, or partly, those accessors, and
the other 11 call source-header inlines built on them. The `unknown-callee`
gap rows fall from 1,247 to 403.

For a file the configuration compiles this is a **correct environment
effect**. The callee's real body became visible, and it is pure. For a file
it does not compile, the body is borrowed from a header generated for a
different configuration, under the same bare name. That is the same pairing
as 2.1, in the opposite direction, and it rests on a fact the primary
configuration supplies, which ADR-0010 Decision 8 says is not proof of
safety. Function bodies are keyed by bare name with no record of the file
they came from, and no lookup consults the include closure (`EffectView`).
So today a header body is visible to every file, whether or not it
includes that header.

### 2.3 Configuration values: ARR30-C (and every `macro_constants` reader)

ARR30-C sizes an array declared with a macro bound from the project macro
table (`const_eval::merged_macro_constants`). `gen_config.h` defines
`CONFIG_MAX_NUM_NODES 1` unconditionally, so every `[CONFIG_MAX_NUM_NODES]`
array becomes size 1 in every file. Without the header the size stayed
symbolic, and the symbolic path flags almost nothing. That silence was
incidental, not an abstention.

The new findings combine a size from the non-SMP configuration with code
only an SMP configuration compiles: an ARM interrupt controller indexing
per-CPU arrays by `CURRENT_CPU_INDEX()`, and an x86-64 file whose whole body
is under `#ifdef ENABLE_SMP_SUPPORT`. That's a Decision 4 misfire. One new
finding is not this: an in-configuration array whose size is now known,
indexed in live code. It is an ordinary adjudication candidate, and the
rule below must keep it.

`merged_macro_constants` has a dozen consumers (INT30–34-C, INT10-C,
FLP03-C, WIN00-C, MEM30-C and analysis passes in `src/analyze/mod.rs`), and
none ties a value to the configuration its use site compiles under. The INT33-C −1 is the benign
case: a division by `CONFIG_WORD_SIZE`, now 64, in a compiled file.

## 3. What is already settled

- **ADR-0005**: a finding that names a construct that isn't there is a bug to
  fix. That covers 2.1 and most of 2.3.
- **ADR-0010**:
  - **D1:** every compilable configuration's arms are reported as written, so
    nothing below suppresses a finding *because* its arm is outside the
    configuration.
  - **D3:** platform and configuration change name resolution and nothing
    else. The rule below is a resolution rule: it decides which facts a name
    resolves to at a use site. Emission then follows from resolution exactly
    as it does when the header is missing.
  - **D4:** combining arms or configurations that never compile together is a
    misfire.
  - **D8:** a fact that follows only from the primary configuration is not
    proof of safety.
- **ADR-0001**: noise is not handled by softening detection. Nothing here
  narrows what a rule looks for. It withdraws facts the tool does not have for
  the code in question, and in 2.2 it restores a finding the borrowed facts had
  withheld.
- **`docs/design/multi-configuration-scanning.md` §7** (option D's second
  limit) already found the general shape: "membership is a property of the
  consumer, not of the definition", so a correct fix needs a view per
  membership rather than one table per scan. This note is that idea applied
  to generated facts, where membership is something the build itself
  declares.
- **`compile_commands.rs`'s own invariant** says that unioning a database's
  include paths "would be wrong for a project that compiles the same header
  name differently per target; no such case exists in the benchmark corpus."
  seL4's per-architecture `arch/object/structures_gen.h` is now that case.

## 4. Recognition, without guessing

Two facts are needed: *which headers are generated*, and *which code the
generating configuration compiles*. Both must come from something the user
or the build declared, never from a file name or a naming convention.

### 4.1 Which headers are generated

| | Source | Name-independent? | Verdict |
|---|---|---|---|
| R1 | An explicit `--generated-include DIR` (repeatable), or the same list in the manifest's scope table | Yes; the user states it | **Recommended**, always available |
| R2 | A compile-database include directory inside some entry's `directory` (its build tree) and outside every project root (the scan path and `-d` directories) | Yes; the database states its build tree | **Recommended** in addition: covers out-of-source CMake builds with no extra flag |
| R3 | Any header git does not track | Infers: vendored and generated look alike, and aurora-lint deliberately never consults git to choose files | No |
| R4 | Any resolved header outside every project root | Can't tell a build tree from a system directory | No |

The benchmark runner would pass R1 for the materialized `${GEN}` tree of
every corpus with a recipe, so in-source builds (sqlite's, pure-ftpd's,
valkey's), whose generated headers `bench.dbbuild` already relocates into
`${GEN}/src`, are covered too. A header reached only through R1/R2
directories is *generated*; a header found first in a source directory is
not, whatever its name. A file in a generated directory with the same bytes as a
project file is a copy, not a generated header (§6.2).

A side effect, left as is in this change (§8, decision 6): today a
resolved generated header outside the project roots is classed as *outside
the project*, like a system header (`MacroOrigins::is_outside`). PRE31-C's library-contract test and
`harvested_from` read that class. A recognised generated header is the
project's own code and arguably belongs on the project side; that is
decided separately.

### 4.2 Which code the configuration compiles

- **M1, files.** A scanned `.c` file is *in the configuration* when it is:
  - a translation unit of the database (`CompileDb::configured_sources`,
    which already exists), or
  - a file a configured translation unit names in a `#line` directive (seL4's
    concatenated `kernel_all.c`), or
  - a file a configured translation unit `#include`s (unity builds).

  All three are statements the build wrote. Headers inherit membership from
  their includer, per use site, as they do today. A scan with no database
  has no generated facts and is unaffected.
- **M2, arms (adopted, §8 decision 3).** Within a member file, a use site is in the
  configuration when its enclosing arms compile under the configuration's
  macro state. That state is the database's `-D`/`-U`, plus the definitions in
  recognised generated headers, plus their absences.
  - Reading an absence as "undefined" is exactly what the compiler does for a
    member file whose include closure fully resolves, so it is the
    configuration's own view, not an assumption.
  - The existing primitive is `dead_regions::arm_assumptions` /
    `line_compiles_under`. Its catalog entry confines it to choosing what a
    name resolves to, never whether a finding is emitted, which is the use
    here.
  - It inherits the substrate's ceiling: `#elif` and arithmetic `#if` are not
    evaluated.

**A bench-side gap M1 exposes:** `bench.dbbuild` keeps only generated
*headers* (`HEADER_SUFFIXES`), so the materialized database names
`kernel_all.c` but the file isn't there. The cache must keep generated
translation units as well, or seL4's 77 members are invisible. This is a
`bench/` change, and the only one this design needs.

## 5. The rule, per effect

One shared mechanism: facts harvested from a recognised generated header
carry that origin.
- **Where they are harvested:** `harvest_header_macros`,
  `fold_header_summaries` and the header-declaration collectors for resolved
  headers.
- **Who sees them:** each analysed file sees them only if it is in the
  configuration (M1), and, with M2, only at use sites in the configuration's
  arms.
- **Everywhere else** the file sees the tables as they would be if the
  generated header were missing. That is the H view, which every rule already
  handles.

This is the "two resolutions, each file reading the one that matches its
membership" of the multi-configuration note, restricted to the facts a
generated header contributes.

- **DCL31-C.** A file outside the configuration whose include closure
  reaches a generated header abstains through the existing
  `incomplete_declarations` path. The scan reports it once through the
  existing `stand_down_report` hook: "undeclared-function check off in N files
  the declared configuration does not compile: their declarations come from
  headers generated for another configuration." That is an
  incomplete-environment notice, not a per-finding annotation. With M2, the
  same applies at a call site in an excluded arm, which also covers the arms
  the syntactic `#if`-ancestor check misses.
- **PRE31-C.** A generated header's function bodies resolve callees only in
  member files (with M2, in member arms). Elsewhere the callee is unproven, as
  before. The strict policy then reports it as it did with the header missing,
  and the default policy credits it as pure. Nothing about macro-definition
  choice changes. The −98 in member files stays, since the real bodies of the
  configuration that compiles that code are now visible.
- **ARR30-C, and every `merged_macro_constants` reader.** A value defined
  only in a generated header sizes an array, bounds a range or folds a
  condition only at a use site the configuration compiles. Elsewhere the name
  is unresolved and stays `Symbolic`, as before.
  - This is placed at the shared table, not in ARR30-C, so INT3x-C, FLP03-C
    and MEM30-C get the same rule (§8 decision 5).
  - The in-configuration case (a known size, live code) keeps its finding.

**Where the origin must be recorded:** at harvest time, against the header's
path. Today function summaries and macro constants are keyed by bare name
with no origin. That is the main cost: a second, smaller view of four
tables plus the effect table, built once per scan, never per file.

## 6. Expected effect

### 6.1 seL4 (derived from the measured data, not from an implementation)

| Rule | H→P today | after M1 | after M1 + M2 |
|---|---|---|---|
| DCL31-C | +191 | +12 (member-file arms) | 0 |
| ARR30-C | +16 | +2 | +1 (the in-configuration candidate) |
| PRE31-C strict | −131 | −98 (member files) | −98, minus however many sit in excluded arms of member files (not yet measured; debug-only `capdl.c` is a member) |
| INT33-C | −1 | −1 | −1 |

Read the "after" columns as a target, not a result. They come from
classifying each changed finding by membership, and the M2 column assumes
every relevant arm is `#ifdef`-shaped and evaluable.

### 6.2 What to watch on the other corpora

Only corpora whose build generates headers can change at all. The build
caches for all twelve recipe corpora, at the environment pinned on
`5fe0fa57`, record what each build generated:

| Corpus | Generated files | Of which byte-identical copies of tracked files | What the rest are |
|---|---|---|---|
| sel4 | 21 | 0 | declaration lists, inline accessors, configuration values |
| sqlite | 45 | 32 | declaration lists (`parse.h`, `opcodes.h`, `keywordhash.h`, …), the public header built from its template, the configure header |
| valkey | 18 | 1 | the vendored allocator's configure output, a release header |
| raylib | 6 | 6 | none: the build copies its own public headers and example resources |
| libcrc | 2 | 0 | generated lookup tables (`.inc`) |
| curl | 1 | 0 | the configure header (`curl_config.h`) |
| pure-ftpd | 1 | 0 | the configure header (`config.h`) |

hostap, lua, mbed TLS, mosquitto and ventoy generate nothing, so this
design cannot change them. hostap's configuration reaches the scan as `-D`
flags, and ventoy's system headers are its dependency set.

**Copies are not generated headers.** raylib's six files and 32 of
sqlite's 45 have the same bytes as files tracked in the corpus: build steps
that copy sources into the build tree (raylib's public headers; sqlite's
`tsrc/` staging copy). They describe no configuration. Recognition
therefore treats a file in a generated directory that is byte-identical to
a file in the project tree as a copy, which is to say an ordinary project
header. The test is content, not name, so it infers nothing. Without it,
non-member files would lose raylib's own API declarations.

Where the change will show: files the database does not compile, which the
scan already counts in its "not compiled by the database's configuration"
warning. Examples are curl's TLS backends and platform files outside the
recipe's build (they read `curl_config.h` today), pure-ftpd's optional
modules, and sqlite sources outside the `USE_AMALGAMATION=0` build.

What to look for there:

- DCL31-C findings disappearing;
- strict PRE31-C findings returning;
- INT3x-C, ARR30-C and FLP03-C findings that used a generated `HAVE_*` or size
  value disappearing or changing.

A change in a *member* file under M1 alone would point at a defect in the
implementation: member files see every fact they see today.

## 7. Fixtures

These extend the `tests/fixtures/cli/dcl31_offswitch/` family (whose
`generated*` cases already cover the missing-header half), as one small
project:

- `src/member.c`, compiled by a fixture `compile_commands.json`;
- `src/other.c`, not compiled;
- a `gen/` directory declared generated, holding `structs_gen.h` (one
  prototype and one static inline accessor) and `config_gen.h`
  (`#define MAX_NODES 1`, and nothing for `FEATURE_X`).

1. **DCL31-C:** `other.c` calls an accessor no generated header declares,
   giving no finding and the stand-down line. `member.c` calls a truly
   undeclared function, so the finding stays (control). With M2, `member.c`
   calls the missing accessor inside `#ifdef FEATURE_X`, including a
   `switch` whose brace straddles the `#endif`, and gets no finding.
2. **PRE31-C strict:** in `member.c`, a skipping macro around a call to the
   pure generated accessor gives no finding (the control for the correct
   environment effect). The same in `other.c` gives a finding.
3. **ARR30-C:** in `member.c`, `int a[MAX_NODES]` indexed by an unvalidated
   parameter keeps its finding (size 1 is real). A whole-file
   `#ifdef SMP` body in a member gives no size and no finding (M2). In
   `other.c` there is no finding.
4. **Membership by `#line`:** a generated unity translation unit naming
   `member2.c` makes it a member.
5. **Recognition:**
   - the same tree with `gen/` passed as a plain `-I` (not R1, outside any
     entry's build tree) behaves exactly as today;
   - with no `--compile-commands`, the output is byte-identical to today.
6. **Negative control:** a project whose database has no generated
   directories gives byte-identical output with and without the change.

## 8. Decisions (2026-10-09)

1. **Recognition: R1 and R2.** An explicit `--generated-include DIR`, and
   compile-database include directories inside an entry's build tree and
   outside every project root. The database counts as a declaration.
2. **Membership: all three M1 sources.** Database translation units, files
   a generated translation unit names in `#line`, and files one `#include`s.
   `bench.dbbuild` keeps generated translation units in the build cache so
   the second source exists for the benchmark corpora.
3. **M2 is adopted.** Arm-level membership applies inside member files. An
   arm the substrate cannot evaluate (`#elif`, arithmetic `#if`) receives no
   generated facts.
4. **Notice: scan-level only, for now.** The stand-down line through the
   existing hook; no per-finding marker.
5. **Breadth: engine-wide.** Origin scoping is applied at the shared tables
   (macro constants, function summaries and the effect table, header
   declarations), so every consumer is covered, not only the three rules
   named here.
6. **Project or outside: unchanged here.** Recognised generated headers stay
   classed as outside the project in this change; whether they should count
   as project code is a separate decision.
7. **DCL31-C's syntactic `#if`-ancestor check** (arms whose braces straddle
   the directive) is a separate fix, diagnosed under ADR-0008, and not part
   of this design.

### Implementation order

Each step is separate and measured on its own:

1. **Build cache keeps generated translation units** (`bench.dbbuild`), so
   `#line` membership is available for the benchmark corpora.
2. **Origin tagging and M1, engine-wide:**
   - recognition (decision 1);
   - origin recorded at harvest time;
   - a per-membership view of the shared tables;
   - the DCL31-C stand-down notice;
   - the fixtures in §7 (1, 2, 3 without the M2 cases, 4, 5, 6);
   - a twelve-corpus A/B.
3. **M2:** arm-level membership with the configuration's macro state, the M2
   fixture cases, and its own twelve-corpus A/B.

The design is complete when steps 2 and 3 have landed and a seL4 A/B
confirms §6.1's targets.

## 9. Relation to other documents

- ADR-0018 introduced the generated-header directories into benchmark scans;
  this note is the analysis side of that change. The environment is
  faithful, and the fix belongs in the tool.
- `docs/design/multi-configuration-scanning.md` §7 is the general version of
  the membership argument. Option D there seeds the profile from `-D`/`-U`;
  §4.2 M2 here adds a generated configuration header's definitions to the
  same state.
- `docs/design/macro-expansion.md` and `compile_commands.rs` describe how a
  database's include paths reach the prescan; §3 above quotes the invariant
  this case breaks.
- `docs/design/realworld-corpus-scope.md` (seL4 section) is where
  "configuration" and "scope" are told apart for scoring. Membership here is
  a resolution input and never a scope or label decision (ADR-0010
  Decision 7).
