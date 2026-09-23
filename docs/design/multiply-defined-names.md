# Multiply-defined names: which file's definition answers for a caller

**Status:** In progress (aurora_lint task 1385). Increments 1 (linkage) and 2
(two statics, at the third attempt) have landed with tests; §5 records what
the first two attempts measured and why they were not landable, because the
reason is the design. Increment 3 is scoped, not built.
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
| `function_summaries`, fields `merge_summary_variant` folds | MAY unions, MUST intersects — each field in the direction its meaning demands | `function_summary.rs`, `merge_summary_variant` |
| `function_summaries`, every other field | **first** definition wins | `prescan.rs`, the `get_mut`/`insert` arm |
| `function_macros` | **first** wins, and a later differing expansion is recorded as a `conflicting-definition` macro gap | `prescan.rs`, the `Entry` match |
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

Landed at the third attempt. The first two are recorded below because the
reason they failed is the finding this section exists for: **scoping a `static` to its file is not a change to the summary
table, it is a change to the key of the whole interprocedural layer.** Every
stage of the prescan resolves a callee by its bare name, and threading a
`(file, name)` key through one stage only moves the problem to the next.
This is the decidable half of what is left, and the "two statics" column
above is its population.

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

What a caller in *neither* defining file should be told is settled by the
same reasoning: nothing. It cannot legally call either definition, so the
name has no project-wide entry unless some file also defines it externally,
and the rules' no-context behaviour is what "unknown callee" already means
everywhere else. This is the one place option (b) belongs.

### What two attempts measured

**Attempt 1** put each file's definition in a side table filled during the
per-file fold. sqlite lost 9 EXP34-C keys, 0 added, every one inside a
`static void usage(const char *argv0)` body. Not the intended effect: a
side-table summary never passes through **phase 4**, where the call-site
aggregation runs, so a scoped definition reached the rules with its real
`dereferences_params` and an empty `callsite_param_null_states`.

That attempt did surface something worth keeping. sqlite defines `usage` as
a `static` in **79** files, and today every one of their call sites is pooled
into a single aggregate under the bare name. The pooling is wrong for exactly
the reason the summary pick is, and nothing made it visible until the scoping
separated them.

**Attempt 2** folded a scoped definition under a `file\0name` key *inside*
the ordinary summary table and qualified that file's call sites to match, so
phase 4 aggregates each definition from its own file alone; a drain step
after phase 4 moves them out, so no consumer sees a qualified key. The unit
test pins the property: two files each defining `static report`, one only
ever handed an array, and only that file's summary proves the parameter
non-NULL.

It still is not enough, and pure-ftpd says why. `sqlsubst` is `static` in
both `log_mysql.c` and `log_pgsql.c`. Measured, one arm at a time:

| | `callsite_param_null_states` for `sqlsubst` |
|---|---|
| before | `{0: NotNull, 1: NotNull, 3..7: PossiblyNull}` |
| after (each file) | `{0: NotNull, 1: NotNull}` |

Params 3–7 are `user`, `ip`, `port`, `peer_ip`, `decimal_ip`, and their
`PossiblyNull` came from `propagate_param_null_states` — a phase-4 pass that
**re-parses every source file** and re-derives call sites keyed by bare name,
seeding each caller's own parameter states as it goes. Its snapshot is keyed
by name, so a qualified entry is invisible to it and the propagation stops
reaching the definition it belongs to. The caller (`pw_mysql_getquery`) is in
the *same file* as the callee, so this propagation was never the cross-file
pooling problem — losing it is an artifact of a half-threaded key, not a
correction. Those 10 removals are the artifact.

The intended effect does show where propagation is not involved: mbedtls
gains API00-C at `psa_crypto_aead.c:318` and `:339` (`mbedtls_psa_aead_*_setup`
does not validate `attributes`), because that file's own `psa_aead_setup`
finally answers for it instead of `psa_crypto.c`'s. That is the acceptance-set
name, behaving as 1385 asks.

Totals across all twelve corpora for attempt 2, one arm at a time, local
numbers and not project figures: 33 keys removed, 46 added. Mixed cause, so
not landable — a half-threaded key trades one arbitrary answer for a
differently wrong one.

### Attempt 3: the key, through every stage that resolves a name

Landed. Three stages have to agree on it, in the order they were found
undoing each other:

1. the per-file fold;
2. the phase-4 aggregation passes, via the file-qualified key;
3. the propagation passes (`propagate_param_null_states`,
   `propagate_param_buffer_sizes`) **and the two collectors they call**,
   which re-derive call sites from source by bare name *and* seed each
   enclosing function's parameter states by bare name. Both directions
   needed scoping, not just the callee keys.

`scoped_name` is the one place any stage turns a name into a key, and the
fold records `file -> names it scopes` so phase 4 resolves the way the fold
did. A file that scopes nothing takes the old path and pays nothing.

The pure-ftpd regression is a unit test rather than a corpus observation now:
two files each with a scoped `subst`, a same-file relay forwarding its own
parameter in, an entry point calling the relay with NULL. Each file's `subst`
gets `{0: NotNull, 1: PossiblyNull}`; with stage 3 disabled param 1 vanishes.

**Two layers are deliberately NOT scoped**, because nothing measured points
at them:

- `call_graph` edges. `ambiguous_call_targets` already marks these names
  opaque to the reachability consumers, and a second representation of the
  same fact looked worse than none.
- the callee names stored *inside* a summary — `returned_callees`,
  `returns_from_callees`, `param_passthroughs`,
  `unconditional_param_passthroughs`, `returned_value_passthroughs`,
  `modifies_params_pending`, `frees_params_by_name`. These matter only where
  a scoped function calls another scoped function in the same file.

### What attempt 3 measured, and what the measurement is worth

All twelve corpora, one arm at a time, local numbers and not project figures.

The raw delta was 33 removed / 46 added at attempt 2 and 154 removed / 48
added at attempt 3 — and most of that growth is **not this change**.
`prescan.rs` caps the null-state propagation at `MAX_PROPAGATION_PASSES = 3`,
and that loop does not run to convergence. Building HEAD with the cap at 8
and changing nothing else removes 108 MEM31-C and 3 EXP33-C keys on sqlite —
the *same* keys attempt 3 removed — and adds 12 EXP34-C. Same binary twice is
byte-identical, so this is not run-to-run nondeterminism; it is a
deterministic but arbitrary stopping point, and any change that perturbs the
seeding moves those findings. Subtracting the keys that move under both
perturbations:

| | keys |
|---|---|
| move under the cap change too (not this change) | 124 removed, 1 added |
| **this change alone** | **21 removed, 47 added** |

Of the 68 that are this change's, every one was read and attributed:

- **Directly inside a scoped static**, whose parameter states stopped being
  pooled with an unrelated same-named function — the intended effect, and
  confirmed per file rather than assumed: curl's `loop` (`curl_fnmatch.c`)
  and `log_line_start` (`tool_cb_dbg.c`); sqlite's tool statics (`usage` and
  neighbours across 79 files); hostap's `wpa_cli.c`/`hostapd_cli.c` pair,
  which define the same nine statics, and `eap_ikev2_process` /
  `eap_tnc_process`, each `static` in both the eap_peer and the eap_server
  implementation of the same method — the same peer-vs-server collision the
  task body names for `struct eap_sm`; mbedtls' `psa_aead_setup`, the
  acceptance-set name, which is also where the two new API00-C findings at
  `psa_crypto_aead.c:318` and `:339` come from.
- **One hop downstream**: a scoped caller's own parameters now resolve from
  its own file, so what it passes on is computed differently. This is the
  hostap INT30-C/INT31-C block, valkey's four, and the singles in lua,
  mosquitto and mbedtls' `cipher.c`.

What that is worth: the mechanism is established for both groups, the
**labels are not**. These 68 keys sit at `(project, commit, file, line,
rule)` tuples the oracle has not adjudicated, so nothing here is a precision
or recall claim in either direction, and a delta-adjudication is the
follow-up rather than something this note can shortcut.

### A behaviour change worth stating on its own

Scoping the call-site aggregation is not only a fix to which *body* answers.
For every name defined `static` in several files, the aggregate under the
bare name stops being the average of every same-named static in the project —
sqlite pooled 79 unrelated `usage` functions' arguments into one answer. That
moves keys whether or not any rule was reading the wrong body, which is why
it belongs in the commit message as its own line rather than as a side
effect.

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
  macro state and `compile_commands.rs` already parses which
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
