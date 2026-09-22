# Multi-configuration scanning: enumeration vs. a declared configuration

**Status:** Research complete (aurora_lint task 1422, 2026-09-22). **Research
document only** — no engine, rule or CLI code was changed to produce it, and
nothing here is an implementation commitment. Follow-up to ADR-0010's
Consequences, which names this as research; scoped to **name resolution
only** per ADR-0010 Decision 3.

**tl;dr recommendation:** do **not** build cppcheck-style configuration
enumeration. Its cost is exponential in a quantity our corpora make large
(free `#if` axes per file: median 2–6, maximum 269), while the prize it buys
is bounded and already enumerable (hundreds of first-wins definition choices
per corpus, which the existing `--report-macro-gaps` already lists by name).
Also do not add a `--platform` *enum* in cppcheck's sense: measured on our own
corpora, a platform axis decides at most ~30% of those choices and the
project's own build configuration decides the rest. Take the two cheap,
already-scaffolded pieces instead: (1) make the assumption table an **input**
— a macro state table, seeded from `--compile-commands`' `-D`/`-U` set, which
`compile_commands.rs` already parses and `dead_regions.rs` never sees; and (2)
**keep the alternatives** where a consumer can use them, generalizing the
`collect_function_macro_alternatives` precedent instead of re-resolving the
file under N tables. §7 has the options table, §8 the follow-ups worth filing.

---

## 1. The question, and what is already settled

ADR-0010 (`every compilable configuration counts`) decides what a finding in a
conditional arm *means*, and in doing so narrows this research sharply. Worth
restating, because three of its decisions remove most of the design space:

- **Decision 1** — a finding in any arm some configuration can compile is
  reported as written. So enumeration cannot be motivated as "reach arms we
  currently skip": no arm is skipped today. tree-sitter parses the file as
  written and every arm is visible to every rule at once.
- **Decision 3** — the platform profile *resolves names*; it never decides
  whether a finding is emitted. A future `--platform` or
  compile-database-derived table "changes name resolution and nothing else".
- **Decisions 6–7** — each oracle describes one stated primary build
  configuration, and other configurations are *other benchmarks* (sel4 x86 vs
  arm vs riscv is three oracles, the way ventoy is the Win32 one), never a
  row's verdict.

What is left is exactly one question: **when a name has several conditional
definitions, which one should a collector keep?** Everything below is about
that and nothing else. The task's framing question — "does aurora-lint ever
need to scan a corpus's non-primary configurations itself?" — is answered by
Decision 7 on the measurement side (onboard the configuration as its own
oracle, no new scanner capability needed, cf. raylib's platform backends,
aurora_lint 1042) and by §5–§7 here on the resolution side.

## 2. What exists today

| Piece | Where | What it does |
|---|---|---|
| One assumption table per scan | `src/analyze/dead_regions.rs`, `platform_assumptions()` | POSIX/Linux profile, six names, hardcoded. Single choke point by design. |
| Seeded dead-region scan | `lang_parsing_substrate::dead_code_ranges_with_assumptions` | Line-oriented single pass; `PlatformAssumptions` is literally a `HashMap<String, bool>`. Local `#define`/`#undef` overrides the seeded assumption. |
| Collectors that consult it | `prescan.rs` (typedefs), `const_eval.rs` (macro constants), `macro_expand.rs` (function-like macros), `macro_gaps.rs` | Skip a definition landing in a dead region, then keep their existing first-wins tie-break for the rest. |
| Keep-every-arm collector | `macro_expand::collect_function_macro_alternatives` | Returns `HashMap<String, Vec<FunctionMacro>>`. Exists because MSC13-C asks a question first-wins cannot answer (sqlite `complete.c`'s `IdChar`). Two consumers today (MSC13-C, MSC37-C). |
| Build flags already parsed | `compile_commands.rs` (`CompileDb::defines`, `define_directives`, `merge_defines_into`) | `-D` minus anything `-U`'d, rendered as real `#define` text and merged gap-filling (`or_insert`) into the macro tables. **Not** fed to `dead_regions`. |
| The blind-spot report | `macro_gaps.rs`, `--report-macro-gaps[=FILE]` | Records the engine's own verdicts, including every definition dropped as dead and every name whose alternatives the profile could not settle. |

Two consequences of that table matter for everything below. First, a
configuration input already exists in the CLI (`--compile-commands`), it
already carries exactly the macro state a configuration is, and it stops one
step short of the place that decides which arm is live. Second, "keep the
alternatives rather than pick one" is not a new idea here — it shipped for two
rules and its doc comment already explains when picking is wrong.

## 3. The two reference points, stated accurately

The task names "cppcheck-style enumeration" and "a `--platform`-style profile
switch". Checked against cppcheck's own documentation, these are not two ways
to do one thing, and one of the two names is misleading:

- **Enumeration** is cppcheck's default: "Cppcheck automatically test
  different combinations of preprocessor defines to achieve as high coverage
  in the analysis as possible." `-D` *restricts* it — "By default Cppcheck
  checks all configurations. Use -D to limit the checking. When -D is used the
  checking is limited to the given configuration" — and `--force` /
  `--max-configs` control how many combinations are tried, with
  `--max-configs` documented as "Maximum number of configurations to check in
  a file before skipping it. Default is 12."
- **`--platform`** is a *different feature*: "Specifies platform specific
  types and sizes. The available platforms are: unix32, unix64, win32A,
  win32W, win64." It sets `sizeof` values, not which arm is live.

So cppcheck's `--platform` is not the thing the task means by "a `--platform`
profile"; the closest cppcheck analogue of our `dead_regions` table is its
`-D`/`-U` restriction. (cppcheck's actual `--platform` — type widths — is a
separate capability aurora-lint may want for width-sensitive INT/EXP rules,
and is out of scope here.) Naming matters for the recommendation: what our
collectors need is a **macro state table**, which is what `PlatformAssumptions`
already is, not an enum of platform names.

Note also that our own real-world suite already runs cppcheck with **neither**
`-D` nor `--force` (`bench/realworld_runner.py::_build_cppcheck_cmd`), so the
competitor column has been an enumerating tool under the default 12-config cap
all along. For its runtime relative to ours, ask `benchmarking_db` rather than
quoting anything from a local db.

## 4. Method for the numbers below

All counts in §5 and §6 are **local diagnostic measurements, not project
benchmark figures**: one node, `aurora-lint 0.5.2` at `6e91dffb`, the twelve
corpus checkouts detached at their pins in `data/benchmark_repos.json`
(`bench corpus-check` clean). They describe the shape of the corpora and of
the engine's own resolution decisions; no precision, recall or finding count
appears here, and none should be read out of this file.

- **Configuration axes (§5)** — for every `.c`/`.h` file in a corpus's
  `scope_include` minus `scope_exclude`: the distinct macro names appearing in
  `#if`/`#ifdef`/`#ifndef`/`#elif` conditions that the tree itself never
  `#define`s anywhere. That is the set of free variables an enumerating
  preprocessor must branch on. Counted twice — arm-selection only
  (`#ifdef`/`#ifndef`/`defined(X)`) and including identifiers in arithmetic
  `#if`; the two differ by a few percent, and the stricter figure is the one
  quoted.
- **Resolution decisions (§6)** — `--report-macro-gaps=FILE` per corpus, with
  the runner's `--exclude` set and a one-rule manifest (gap collection is
  prescan- and audit-driven, so it is rule-independent: hostap's full-manifest
  run and its one-rule run produced byte-identical gap totals). Rows were then
  classified by walking the enclosing `#if` stack of each reported definition
  and asking whether any name in it is a compiler/OS-predefined platform macro
  (`_WIN32`, `_MSC_VER`, `__GNUC__`, `__APPLE__`, `__arm__`, `__BYTE_ORDER`, …
  ~70 names), with one level of transitivity: a build-config name whose only
  `#define` sites in that file sit inside platform-decided arms counts as
  platform-derived (sqlite's `HAVE_MKDIR_ONE_ARG`, defined only under
  `_MSC_VER`/`__MINGW32__`).

The classifier attributes by *syntactic* enclosure plus one transitive hop, so
it under-counts deeper platform derivation; treat the platform share as a
lower bound and the build share as an upper bound. The direction of the
conclusion in §6 survives either reading. The scripts were one-off local
analysis, deliberately not committed (they are not something a fresh clone
needs — same test as everywhere else in `CLAUDE.md`); the two paragraphs above
are the specification.

## 5. What enumeration costs on our own corpora

Per-file free configuration axes, arm-selection only, in-scope files:

| corpus | in-scope files | with ≥1 free axis | free names, tree-wide | median axes (of those) | p90 | max |
|---|---|---|---|---|---|---|
| hostap | 736 | 357 | 373 | 2 | 6 | 58 |
| curl | 427 | 292 | 389 | 2 | 6 | 98 |
| valkey | 229 | 66 | 116 | 2 | 3 | 47 |
| sqlite | 214 | 185 | 317 | 3 | 11 | 105 |
| sel4 | 183 | 143 | 86 | 2 | 6 | 15 |
| mosquitto | 179 | 117 | 63 | 2 | 5 | 19 |
| mbedtls | 174 | 156 | 603 | 6 | 23 | 269 |
| pureftpd | 131 | 88 | 356 | 4 | 14 | 108 |
| lua | 65 | 21 | 41 | 2 | 2 | 15 |
| raylib | 23 | 20 | 71 | 6 | 16 | 22 |
| ventoy | 22 | 4 | 5 | 1–2 | 1 | 2 |
| libcrc | 19 | 3 | 2 | 1 | 1 | 1 |

The extremes are not exotic files: `mbedtls/library/version_features.c` (269),
`pureftpd/src/ftpd.c` (108), `sqlite/src/sqliteInt.h` (105),
`curl/lib/curl_setup.h` (98), `hostap/wpa_supplicant/wpa_supplicant.c` (58).
They are the configuration-dense files every scan must read anyway — the
generated feature list, the daemon's main translation unit, the umbrella
headers.

Three things follow.

1. **The cap does the deciding, not the analysis.** 2^n configurations against
   a cap of 12 means the cap binds above 3 axes. That is 78 files in sqlite,
   80 in curl, 114 in hostap, 114 in mbedtls. On a 98- or 269-axis file, "12
   configurations" is an arbitrary sample of 2^98, and which twelve depends on
   enumeration order, not on which configuration anyone builds. A tool whose
   answer on `curl_setup.h` depends on its enumeration order is not measuring
   a configuration; it is sampling one.
2. **Cost is a multiplier on the whole pipeline, not on a cheap pass.** Our
   collectors are per-file and the assumption table is per-scan, so
   "enumerate" means re-running prescan and the per-file collectors under k
   tables, then re-running every rule against each resulting context. There is
   no preprocessor to amortize it against, and the prescan cache is a
   serialized single `ProjectContext` (`--save-prescan`/`--load-prescan`), so k
   tables mean k caches.
3. **Aggregation collides with ADR-0010 Decision 1.** Every arm is already
   reported under one table. Under k tables the only Decision-1-consistent
   aggregation is the *union* over configurations — report a finding if any
   configuration produces it — which strictly grows the finding set, and every
   new finding lands at a `(project, commit, file, line, rule)` key that was
   never adjudicated. The scanner-side cost is k×; the measurement-side cost
   is a whole-corpus delta-adjudication before any precision statement can be
   made again. That is the expensive half, and it buys no new arm coverage
   (Decision 1) — only different name resolutions.

## 6. What the prize actually is

The same `--report-macro-gaps` the engine already carries lists every decision
enumeration would change. Name-resolution kinds only (the rest —
variadic/paste/unresolved-include/unknown-callee — are other blind spots and
untouched by configuration choice):

| corpus | definitions dropped as dead | first-wins among live alternatives | arity mismatches |
|---|---|---|---|
| hostap | 69 | 10 | 621 |
| curl | 49 | 80 | 10 |
| sqlite | 60 | 141 | 23 |
| mbedtls | 9 | 75 | 13 |
| valkey | 68 | 69 | 162 |
| ventoy | 40 | 137 | 56 |
| raylib | 63 | 9 | 3 |
| sel4 | 1 | 38 | 12 |
| mosquitto | 14 | 40 | 0 |
| lua | 8 | 40 | 20 |
| pureftpd | 0 | 21 | 0 |

Tens to low hundreds per corpus, **by name, with file and line, already
printed**. That is the whole quantity an exponential enumeration would buy
back. It is small enough to attack directly, and — the point of the report —
it is already visible per scan rather than inferred.

Which axis decides those choices, across the eleven corpora with rows
(1,041 rows total):

| kind | rows | build-config axis | platform axis in the stack | transitively platform-derived | indeterminate |
|---|---|---|---|---|---|
| first-wins among live alternatives | 660 | 451 (68%) | 176 (27%) | 20 | 13 |
| dropped as dead | 381 | 195 (51%) | 153 (40%) | 25 | 8 |

**A platform switch is aimed at the smaller half.** Roughly two-thirds of the
first-wins choices are decided by a name the project's own build sets, not by
a compiler-predefined platform macro. The canonical shape is sqlite's

```c
#if defined(SQLITE_OMIT_AUXILIARY_SAFETY_CHECKS)
# define ALWAYS(X)      (1)
#elif !defined(NDEBUG)
# define ALWAYS(X)      ((X)?1:(assert(0),0))
#else
# define ALWAYS(X)      (X)
#endif
```

— three definitions on two independent axes, neither of them a platform. First
wins, so the engine holds `ALWAYS(X) → (1)`: a constant, from the
omit-safety-checks build, for a corpus measured under a normal one. No
`--platform=unix64` fixes that; `-DNDEBUG` or its absence does. It is also
precisely the territory of ADR-0010 Decision 5 (an `assert` is gone under
`NDEBUG` and evaluated without it, and neither configuration is privileged) —
which is an argument for making the choice *declared and visible*, not for
guessing better.

**A second reading of the same table:** about half the rows the report labels
"dropped as platform-dead under the POSIX profile" are nothing of the kind —
they are arms the file itself proves dead, which is ADR-0010 Decision 2
working exactly as intended. hostap's `src/crypto/aes_i.h` has an
unconditional `#define AES_SMALL_TABLES` above its `#ifndef AES_SMALL_TABLES`
block, so the large-table `RCON`/`TE0`… definitions in that arm are dropped on
local evidence with no assumption involved. The substrate distinguishes these
(`DeadCodeReason::{IfZero, CppOnly, AlwaysDefined, NeverDefined}`);
`DeadRegions` discards the reason when it maps regions to line ranges, so the
report attributes all of it to the profile. Nothing analyses wrongly because
of this — the drop is correct either way — but it inflates the apparent reach
of the platform table, which is the exact quantity this research is about.
See §8.1.

## 7. Options

| | What it is | Cost | Complexity | FP / measurement risk | Verdict |
|---|---|---|---|---|---|
| **A** | cppcheck-style enumeration: k assumption tables per file, k collector+rule passes, union the results | k× the whole pipeline; cap binds above 3 axes on 80–115 files per large corpus | High: cache keyed per context, k-way merge, per-config attribution in findings | Union semantics (forced by Decision 1) grows the finding set into unadjudicated `(file, line, rule)` keys → whole-corpus re-adjudication before the next precision claim | **No** |
| **B** | `--platform` enum switch (`posix`/`win32`/…) selecting a canned table | ~0 runtime; `platform_assumptions()` is already the one choke point | Low | Default unchanged ⇒ zero delta; a non-default profile changes name resolution only | **Not on its own** — addresses ≤30% of the choices (§6), and its vocabulary can't express `NDEBUG` or `CONFIG_SAE` |
| **C** | Keep alternatives: generalize `collect_function_macro_alternatives`, let the consumer pick from local context | ~0 runtime (same line scan); memory linear in alternatives, which §6 bounds at hundreds per corpus | Medium, but **per-consumer and opt-in** — MSC13-C is the shipped precedent | Per-rule gated, so measurable one rule at a time, the way every other engine capability was rolled out | **Yes, as the primary line** |
| **D** | Assumption table as input: seed `PlatformAssumptions` from `--compile-commands`' `-D`/`-U`, or an explicit `-D`/`-U`/profile flag | ~0 runtime; the flags are already parsed and the type is already a `HashMap<String, bool>` | Low — one function plus plumbing that exists | Off by default ⇒ zero delta. With a database, resolution follows the configuration the project actually builds; hits the build-config majority B cannot reach | **Yes, cheapest real win** (shipped, task 1430; see the ceiling below) |

### D's ceiling: `#elif` is not evaluated (measured while implementing, task 1430)

`lang_parsing_substrate`'s dead-region scanner classifies `#if`, `#ifdef`,
`#ifndef` and the matching `#else`; an `#elif` condition is never evaluated —
it only closes a region the opening `#if` started. A declared macro state
therefore cannot settle a choice whose arms are separated by an `#elif`, no
matter how complete the declaration is. Of the 660 first-wins choices in §6,
**524 (79%) are structurally reachable** by a declaration and **136 (21%) sit
in `#elif` arms** (sqlite 28, ventoy 30, valkey 20, mbedtls 18, curl 13,
pureftpd 11, lua 9, raylib 5, mosquitto 2, hostap 0, sel4 0).

sqlite's `ALWAYS(X)` above is in the blocked 21%: its `NDEBUG` arm is an
`#elif`, so `-DNDEBUG` does not currently resolve it. It remains the right
illustration of *which axis decides* — that point is unaffected — but not of
what D fixes today. `dead_regions.rs` pins this ceiling in a test
(`an_elif_arm_is_beyond_what_a_declaration_can_settle`) so that if the
substrate later learns `#elif`, the change shows up as a failing test rather
than as a silent behaviour shift. Teaching it `#elif` is a substrate-side
follow-up worth its own task; it would widen D's reach by about a quarter.

### D's second limit: the declaration is per scan, the database is per file

Measured on hostap with a declaration derived from its own `defconfig`
(task 1430; the `-D`/`-U` set is the defconfig-enabled `CONFIG_*` names the
Makefiles turn into flags, so it is a real hostap configuration, though not
necessarily the one `make` builds from that file — `make`'s conditional
side-effects are not followed):

- **The payoff, where the file is in the build:** arity-mismatch gap rows fall
  from 621 to 197. hostap defines `wpa_printf(args...)` as a no-op macro under
  `#ifdef CONFIG_NO_STDOUT_DEBUG`; that is the only *macro* definition of the
  name, so first-wins held a one-parameter definition against every real
  four-argument call. `-UCONFIG_NO_STDOUT_DEBUG` drops it and 424 of those
  mismatches with it.
- **The cost, where the file is not:** three findings appear (INT32-C ×2,
  PRE31-C ×1), and all three are in files the declared configuration does not
  compile. `-UCONFIG_CTRL_IFACE_UDP` kills the arm defining
  `WPA_CTRL_IFACE_PORT`, so `int port = WPA_CTRL_IFACE_PORT;` in
  `ctrl_iface_udp.c` loses its range and INT32-C flags the `port--` retry.
  `-UCONFIG_FST` kills all of `fst.h`, so PRE31-C loses the definition that
  exonerated `FST_LLT_VAL_TO_MS` (its parameter occurs once) and falls back to
  treating an ALL_CAPS call with a function-call argument as unsafe.

The asymmetry is structural, not a tuning problem: a compile database is
per-translation-unit and the profile is per scan, so a file outside the declared
configuration gets resolved under a configuration that excludes it. The fix is
to scope the declaration the way the database is scoped — a file with no entry
is not part of that configuration and should resolve under the default profile —
which needs `RawEntry::file` (deliberately not deserialized today) threaded to
the per-file collectors. Filed as a follow-up; **not** worth trading for the
tempting cheap version, "only apply the declaration where the name has another
live definition in the file", which would have kept both dropped constants and
also kept the no-op `wpa_printf`, losing the entire payoff above.

On mosquitto, with a declaration derived from `config.mk`'s own defaults, the
finding set is byte-identical and exactly one resolution changes:
`SSL_DATA_PENDING` in `lib/tls_mosq.h`, real check under `#ifdef WITH_TLS`
versus `0` in the `#else` stub, stops being a first-wins guess and becomes
known. First-wins happened to be right there; nothing says it would be if the
arms were written in the other order.

**Recommendation: C + D, and B only as a fallback shape for corpora with no
compile database** (a canned profile is then just a hand-written table for the
same mechanism, which is why D should define the table type and B, if it ever
lands, should be sugar over it — not a parallel concept).

The reasoning in one line: enumeration pays an exponential cost to recover a
set the engine can already name, while the two mechanisms that recover the
same set cost nothing at runtime and stay opt-in, so each can be measured
against the oracle independently, per ADR-0010 Decision 3 ("changes name
resolution and nothing else").

**Deliberately not proposed**, to keep this consistent with settled policy:

- Any `--assume-defined`/`--platform` switch that *suppresses findings*. That
  is a proposal to revisit ADR-0010, not a feature (its Consequences say so
  outright).
- Reporting across arms, or gating a rule on arm liveness (Decision 4 /
  ADR-0005).
- Promoting anything new into `lang_parsing_substrate`. C and D live in
  `src/analyze/` per ADR-0003; the one substrate-side item is §8.1, which is a
  *return-value* change to an API we already call.

## 8. Follow-ups worth filing (each small, each independent)

1. **Keep `DeadCodeReason` through `DeadRegions`** and split the gap kind
   accordingly (`platform-dead` vs `locally-dead`). `DeadRegions::of` already
   throws the reason away; the substrate already computes it. Without this, no
   future measurement of "how much does the profile decide" can be taken at
   face value — §6 had to reconstruct it by re-parsing the corpus.
2. **Seed the assumption table from `CompileDb`** (option D). Mind the
   asymmetry: compile-database `-D` merges gap-filling (`or_insert`) into the
   macro tables so real source always wins, and the substrate independently
   lets a local `#define`/`#undef` override a seeded assumption — the two
   precedence rules already agree, which is why this is plumbing rather than
   design.
3. **Generalize alternatives to object-like macros and typedefs** (option C)
   — but only behind a named consumer. Its two function-like consumers
   (MSC13-C, MSC37-C) are what make the tie-break policy defensible; an
   object-like or typedef consumer should arrive the same way, with its own
   rule-level gate.
4. **Align with the per-corpus primary-configuration declaration.** This
   landed while 1430 was in flight: `primary_build_config` is now on all twelve
   entries of `data/benchmark_repos.json` (`cf98ae7e`), with a per-project
   rationale in `realworld-corpus-scope.md`. It declares platform, arch,
   endianness, toolchain and the in-scope paths that configuration never
   compiles — *not* a macro state, and hostap's summary points at "their
   shipped defconfigs" rather than enumerating `-D` flags. So a scan cannot
   consume it as a profile as it stands: option D needs either a compile
   database per corpus (what `playbooks/setup-compile-commands.yml` generates)
   or a macro-state field alongside it. Worth deciding which, before anything
   tries to read the field.

## 9. Relation to the existing docs

- `docs/design/macro-expansion.md` §9's third open question ("which `#if`
  branch is 'live' when a macro has multiple definitions?") is the question
  this note scopes. §12 closes by saying the report "makes its cost visible per
  scan rather than answering it" — §6 is that cost, measured.
- `docs/design/macro-expansion-v2-audit.md` reached the structurally identical
  conclusion one layer up: no general pre-expansion pass, three narrow
  capabilities instead. Same shape of answer, same reason (the blast radius of
  the general mechanism is large; the unmet need is small and enumerable).
- ADR-0010 is the policy this obeys; ADR-0003 decides where C and D live;
  ADR-0001/0005 are why no option here touches finding emission.
