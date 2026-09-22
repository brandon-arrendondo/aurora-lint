# Multiply-defined names: which file's definition answers for a caller

**Status:** In progress (aurora_lint task 1385). Increment 1 (linkage) has
landed with tests; increments 2 and 3 are scoped here and not built.
Companion to `multi-configuration-scanning.md`, which asks the same
resolution question one level down: that note is about which **arm** of one
file's `#if` wins, this one is about which **file** wins. Neither changes
whether a finding is emitted (ADR-0010 Decision 3).

**tl;dr:** the prescan folds per-file results into one table per name, and for
every field the fold does not merge the answer is one definition picked
arbitrarily. Three different things hide under "arbitrary", and only two of
them are decidable from the source at all:

| Mechanism | Shape | Decidable from source? |
|---|---|---|
| **Linkage** | `static` in one file, external in another | **Yes** — a caller in any other translation unit links the external one. Fixed (§4). |
| **Two statics** | `static` in two or more files, nowhere external | **Yes** — they are unrelated functions; only a caller in the defining file may use one. Needs a per-file view (§5). |
| **Two externals** | external in two or more files | **No** — the build configuration links one (hostap's `os_*` layer, the TLS and crypto backends). This is `multi-configuration-scanning.md`'s question, not this one (§6). |

Task 1385's stated options — (a) same-TU wins, (b) resolve to nothing, (c) key
per definition — are each right for a different one of those rows, which is
why none of them works as a single rule.

---

## 1. What the merge does today

`prescan.rs` parses every file in parallel and then folds the results
sequentially into one `ProjectContext`. The fold is per name, and its
direction varies by table:

| Table | Fold | Site |
|---|---|---|
| `function_summaries`, fields `merge_summary_variant` folds | MAY unions, MUST intersects — each field in the direction its meaning demands (tasks 401, 1065, 1079, 1217) | `function_summary.rs`, `merge_summary_variant` |
| `function_summaries`, every other field | **first** definition wins | `prescan.rs`, the `get_mut`/`insert` arm |
| `function_macros` | **first** wins, and a later differing expansion is recorded as a `conflicting-definition` macro gap (task 1180) | `prescan.rs`, the `Entry` match |
| `restrict_params` | **first** wins (`or_insert`) | `prescan.rs` |
| `documented_nonnull_params` | unions the indices | `merge_documented_params` |
| `typedef_types`, `struct_field_types`, `struct_typedef_aliases`, `macro_constants`, `macro_aliases`, `global_constants`, `global_var_null_states` | **last** wins (`HashMap::extend` overwrites) | `prescan.rs` |
| `known_functions`, `noreturn_functions`, `packed_structs`, … | set unions, order-free | `prescan.rs` |

Two corrections to what task 1385's body and the `4ac5710f` commit message
say, both checked rather than reasoned about:

- The non-folded **function-summary** fields are **first**-wins, not
  last-wins. Verified on the real corpus: with raylib's `raudio.c` reached
  before `rcore.c`, the merged `SaveFileText` carried `raudio.c`'s
  `checks_null_params = {0, 1}`, and `rcore.c`'s later `{0}` did not displace
  it. Last-wins is right for the `extend`-merged tables in the row above.
- The fields that fold were not quite order-free either: the
  `frees_params_guessed` bookkeeping read each variant's evidence off the
  *union* rather than off that variant, so which side was folded into which
  changed the answer. Fixed in §4, because §4 needs to swap the sides.

Sorting the walk (`4ac5710f`) made the pick deterministic, not right: it is
whichever definition sorts first by file name.

## 2. Which fields the arbitrary pick governs

The fields `merge_summary_variant` does not fold, and so the ones a pick
decides:

`checks_null_params`, `checks_null_params_before_deref`,
`dereferences_params`, `nulls_params`, `frees_param_pointees`,
`distinct_object_param_pairs`, `has_internal_linkage`, `never_returns`,
`produces_param_buffer_size`, `return_range`,
`returns_only_compile_time_constants`, `variadic_from`.

The `callsite_param_*` fields are also unfolded, but phase 4 recomputes them
from project-wide call-site tables, so a pick does not decide them.

## 3. How big each mechanism is

Sizing only, from the per-corpus `ctags` indices over the **whole checkout**,
including trees each oracle's scope excludes (raylib's `examples/` and
`tools/`, sqlite's `ext/`, test harnesses). A name counts once however many
files define it. These are local counts for sizing the work, **not** project
figures and not a measurement of anything: they say nothing about findings.

| corpus | two statics | files holding them | linkage mix | two externals |
|---|---|---|---|---|
| curl | 62 | 82 | 5 | 37 |
| hostap | 348 | 164 | 19 | 795 |
| libcrc | 0 | 0 | 0 | 1 |
| lua | 1 | 2 | 12 | 61 |
| mbedtls | 78 | 38 | 5 | 15 |
| mosquitto | 65 | 52 | 35 | 355 |
| pureftpd | 20 | 13 | 2 | 5 |
| raylib | 35 | 24 | 30 | 318 |
| sel4 | 50 | 46 | 29 | 565 |
| sqlite | 186 | 81 | 16 | 170 |
| valkey | 77 | 76 | 49 | 126 |
| ventoy | 569 | 155 | 43 | 433 |

Two things this table decides:

- The undecidable row is the **largest** one. Whatever 1385 does, most
  multiply-defined names stay a configuration question.
- "Files holding them" is what bounds §5's cost: a per-file view is needed
  for at most 164 files in the largest corpus, not for every file scanned.

`4ac5710f`'s own acceptance set classifies the same way — which is why one
rule could never have covered it:

| Name | Files | Mechanism |
|---|---|---|
| raylib `SaveFileText`, `SaveFileData`, `LoadFileData`, `GetFileName`, … | `raudio.c` (static) / `rcore.c` | linkage |
| mbedtls `psa_aead_setup` | `psa_crypto.c`, `psa_crypto_aead.c` | two statics |
| sqlite `SHA3Update` (3), `openDatabase` (2) | `shathree.c`, `mksourceid.c`, `src-verify.c`; `main.c`, `showdb.c` | two statics |
| hostap `freq_included` | `dpp.c`, `p2p_supplicant.c` | two statics |
| hostap `os_*`, `crypto_*_deinit`, `tls_*` | `os_unix.c`/`os_internal.c`/`os_none.c`; `crypto_openssl.c`/`crypto_wolfssl.c`; five `tls_*.c` | two externals |
| sqlite `sqlite3_open`, `sqlite3_open_v2` | `main.c`, `sqlite3-jni.c` | two externals |
| sqlite `u16` (10 definitions), hostap `struct eap_sm` | typedef / struct-field tables | two externals, via the include graph |
| sel4 `IDX_TO_IRQT` | per-arch macro headers | two externals |

## 4. Increment 1: an external definition outranks a static one elsewhere

Landed. At the prescan fold, when the held definition has internal linkage
and the incoming one does not, the incoming one becomes the base and the
static one is folded into it. The MAY/MUST folds are unchanged, so nothing a
static body might do is lost from the safe direction; what changes is which
definition governs §2's fields.

It also stops `has_internal_linkage` being claimed for a name whose real
definition is external. That claim is not cosmetic:
`null_state.rs::collect_proven_nonnull_params` reads it as "every call site of
this function is in the scanned set" and credits the callee's parameters as
proven non-NULL on that basis. A static in another file could hand a name that
credit by sorting first.

**Measured effect: none.** Local A/B, one arm at a time, release binaries
built before and after and kept outside the tree, each corpus scanned with
the command `bench/realworld_runner.py` would build for it (same manifest,
same excludes, same `-d`). Byte-identical finding sets on all twelve pinned
checkouts — 0 keys added, 0 removed, every corpus. Local numbers, not project figures; nothing here is a precision
claim, and with no key moved there is nothing to delta-adjudicate.

Verified at the level the change acts on instead, on the real raylib
checkout: `SaveFileText`'s merged summary goes from
`has_internal_linkage = true, checks_null_params = {0, 1}` to
`has_internal_linkage = false, checks_null_params = {0}` — i.e. from
`raudio.c`'s static body, which null-checks `text`, to `rcore.c`'s external
one, which does not.

Why the labeled EXP34-C true positive at `rcore.c:2297` does **not** come
back with it: neither body dereferences `text` (both only pass it to
`fprintf("%s")`), so `dereferences_params` is empty on both sides, and the
key is absent from the before side too. Whatever else EXP34-C needed at
`4ac5710f` has changed in the commits since; the summary-level pick it was
attributed to is fixed, and the key is not a live acceptance criterion for
this increment.

So increment 1 is a latent-correctness fix at no measured cost, not a
finding-count change.

## 5. Increment 2: a static definition answers only in its own file

Not built. This is the decidable half of what is left, and the "two statics"
column above is its population.

Two `static` definitions of one name in different files are two unrelated
functions. Today one of them answers for every caller in the project; the
other file's callers get a summary of a function they cannot call. Note the
asymmetry that makes "resolve to nothing" (option (b)) the wrong answer here:
*every* legal caller of a static definition is in its own file, so dropping
the entry is worse than today's pick, which at least serves the first file's
callers correctly.

`prescan.rs` already computes the exact name set — `static_defining_files`,
whose `files.len() > 1` names it already pushes into
`ambiguous_call_targets`. Only the call-graph consumers honour that marking;
`function_summaries` still hands every rule an arbitrary pick.

One gap to close with it: `local_static_functions` is collected from headers
too, but `static_defining_files` is only filled where `source_path` is set,
and that is `.c`-only by design. A `static inline` in a header — defined once
in the source, compiled into every translation unit that includes it — is
therefore invisible to the existing marking as well as to any per-file view
built on it.

The seam for a per-file answer exists and is cheap.
`analyze::mod` installs the context **per file**, inside the scan loop
(`set_project_context_for_enabled(&file_registry, manifest, &context)`, both
the parallel and the sequential path), with `file_path` in scope. So:

- keep a side table of the definitions of each ambiguous-static name, by
  defining file;
- for a file that defines one, install a context whose `function_summaries`
  holds that file's own definitions in place of the project-wide pick;
- for every other file — all but at most ~164 per corpus, §3 — pass the
  shared context unchanged, at today's zero cost.

`ProjectContext` is `Arc`-per-table for exactly this reason (its module doc:
a deep copy per rule per file was once the dominant scan cost), so the
specialized context copies one table for a handful of files. Check
`global_constants`, which is a bare `HashMap` rather than an `Arc`, before
cloning the struct per file.

What a caller in *neither* defining file should be told is the open question:
nothing (it cannot legally call either) is the sound answer, and is where
option (b) belongs.

## 6. What increment 3 cannot decide, and should not pretend to

The "two externals" column is a build-configuration question and belongs to
`multi-configuration-scanning.md`: which of `os_unix.c`, `os_internal.c` and
`os_none.c` is compiled is not written in any of them. Same for the crypto
and TLS backends, sel4's per-arch macro headers, sqlite's `u16` (ten
definitions, the include graph decides), and hostap's two `struct eap_sm`
declarations (`eap_peer/eap_i.h` vs `eap_server/eap_i.h`, `num_rounds` `int`
in one and `unsigned` in the other).

Two honest routes, both already scaffolded, neither one "pick better":

- **Declare the configuration.** `--compile-commands` already declares the
  macro state (task 1430) and `compile_commands.rs` already parses which
  files the build compiles (task 1432, `configured_sources`). A definition in
  a file the declared build does not compile is the one to drop. This is the
  per-TU scoping 1432 stopped short of, and it needs a real
  playbook-generated compile database to be worth anything.
- **Keep the alternatives.** `collect_function_macro_alternatives` is the
  precedent: hand the consumer every definition and let the rule that can use
  them use them (MSC13-C, MSC37-C do). Option (c), scoped to the consumers
  that can answer the question.

Until one of those lands, the pick among two externals stays deterministic
and arbitrary, and saying so is better than a rule that looks principled and
is not.

## 7. Relation to the existing docs

- `ADR-0006` is the neighbouring lesson: resolve an identifier, never match
  its spelling. This note is the same lesson one scope up — a *name* is not a
  key, a `(file, name)` pair is.
- `ADR-0010` Decision 3 bounds all of it: resolution never suppresses a
  finding.
- `multi-configuration-scanning.md` §6–7 holds the arm-level half of the
  question, and §6 above is its file-level continuation.
- `internal-capability-catalog.md` describes the first-wins tie-break inside
  `collect_function_macros`; §1's table is the cross-file counterpart.
