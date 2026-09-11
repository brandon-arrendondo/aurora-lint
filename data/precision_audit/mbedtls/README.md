# mbedtls onboarding — 10th real-world oracle (crypto/TLS library, MEM03-C focus)

Onboarded 2026-09-11 (aurora_lint task: "Onboard mbedtls (library/) as 10th
real-world benchmark codebase"). First scan: local run #223 on this checkout,
binary at the onboarding commit, corpus-check clean — **11,501 findings across
146 of the 174 in-scope files, 150,412 LOC, 25.0 s**. Nothing is adjudicated
yet; every number here describes this checkout's own run, not a project
measurement (see the repo `CLAUDE.md`).

## Why this codebase

The suite had nine oracles and no dedicated cryptographic library. mbedtls
carries `mbedtls_platform_zeroize`, a real, purpose-fit sensitive-data-clearing
idiom (224 call sites in `library/*.c`) that no earlier codebase offered
MEM03-C — the same "pick a codebase for one rule's first real signal" logic
that brought in pureftpd for CWE-89. The other draw is `mbedtls_calloc` /
`mbedtls_free` (169 allocation sites), which are `#define`d aliases in
`include/mbedtls/platform.h`, a shape none of the nine had at this density.

## Candidate

[Mbed-TLS/mbedtls](https://github.com/Mbed-TLS/mbedtls) `v3.6.7` →
`068ff080b369adfac81509f9b57b2afabaf82dc5` (tag resolved locally to the same
SHA; Apache-2.0 OR GPL-2.0-or-later). Checkout directory `mbedtls`, lowercase,
matching the registry key. The `framework/` submodule is deliberately left
uninitialised — it is test tooling and outside scope. No build step is needed:
`mbedtls_config.h` and `build_info.h` are static checked-in headers, and
`git ls-files --others --ignored` finds no `.c`/`.h`, so there is nothing for
`corpus-check` to flag as contamination.

## Scope: `library/**`

The machine-readable mirror in `data/benchmark_repos.json` is
`"scope_include": ["library/**"]` with no exclude list: `library/` holds
exactly the shipped library (109 `.c` + 65 `.h` = 174 tracked files) and
nothing else. Everything outside it is out of scope by construction:

- `include/mbedtls/`, `include/psa/` — public headers only. Excluded for the
  same reason curl excludes its own `include/`: not shipped-product code in the
  `library/` sense, and findings there would sit outside the audited
  denominator. They are still prescanned (`-d {path}/include`) so macro,
  typedef and enum resolution for `library/` is intact — that is where
  `mbedtls_calloc`/`mbedtls_free` are defined.
- `3rdparty/` — vendored Project Everest verified crypto.
- `tests/`, `programs/` (incl. `fuzz/`), `scripts/`, `configs/`, `visualc/`,
  `framework/` — test harness, sample programs, tooling.

Runner entry (`bench/realworld_runner.py`): `scan_path {path}/library`,
`-I {path}/include -I {path}/library`, `-d {path}/library -d {path}/include`.
`library/` is in `-d` on purpose (the sel4 entry omitted its own scan dir and
lost every cross-file caller — aurora_lint task 987).

## Manifest: `conf/realworld/mbedtls-rules.toml`

`aurora-lint --detect-relevance` on `library/` reports `threading=true,
windows=true` — real `MBEDTLS_THREADING_PTHREAD` code in `threading.c` and
`_WIN32`-conditional code in `net_sockets.c`, `entropy_poll.c`, `timing.c`,
`platform_util.c`, not false positives — so no CON*/WIN* gating applies. The
manifest is the full `rules_templates/rules-all.toml` with only the four
suite-wide dead-config disables (ENV04-C, MSC18-C, MSC19-C, MSC25-C), the same
shape as pureftpd and sel4. Threading is opt-in in mbedtls (off by default) but
the code is there and the rules are cheap; per-finding truth is the oracle's
job.

## First-scan shape (run #223, unadjudicated)

Top rules by volume: API00-C 1,802 · DCL06-C 1,630 · MSC13-C 1,072 · PRE31-C
911 · PRE08-C 336 · EXP34-C 326 · DCL13-C 283 · EXP05-C 273 · EXP43-C 268 ·
EXP02-C 221. The same advisory-heavy head as every other oracle; nothing here
is a categorical-disable candidate under the README's category 3 (the largest
rule is 15.7% of this codebase's output, and this codebase is ~8% of the
suite's).

### MEM03-C: the signal this codebase was onboarded for — 10 findings, all "not cleared before function exit"

The three read at source (`ssl_tls13_keys.c:344` `tmp_secret`,
`psa_crypto.c:7827` `shared_secret`, `ssl_tls.c:7156` `other_secret`) each
clear the buffer with `mbedtls_platform_zeroize` on every path that reaches
the function's exit label (`goto cleanup` / `goto exit`); the only early
`return` in the first function precedes any write to the buffer. The rule's
clearing-call table (`CLEAR_FUNCS` in `mem03_c.rs`: `memset`, `memset_s`,
`explicit_bzero`, `bzero`, `SecureZeroMemory`) does not contain
`mbedtls_platform_zeroize`, so it cannot see any of the 224 clearing sites.
Expect the 10 to adjudicate as FP for that one reason. Filed as a rule
follow-up (see the task DB); the fix should recognise a clearing *wrapper* by
what its body does (`platform_util.c:mbedtls_platform_zeroize` is `memset` via
a volatile function pointer), not by adding one more name.

### MEM30/31-C and the `mbedtls_calloc` / `mbedtls_free` aliases — checked, not assumed

The task asked whether MEM30/31-C resolve these by name or need a
`macro_expand.rs` entry. Answer: **neither sees the allocator.**
`include/mbedtls/platform.h` defines them as *object-like* aliases
(`#define mbedtls_calloc calloc`, `#define mbedtls_free free` under the
default `!MBEDTLS_PLATFORM_MEMORY` branch), and `macro_expand.rs` handles
function-like macros only — its own header says object-like macros are
`const_eval`'s. A two-function probe (`p = mbedtls_calloc(1, 32); return 0;`
next to the same with `calloc`) reports the `calloc` leak and not the
`mbedtls_calloc` one, with or without `-d include`. So MEM31-C's zero leak
findings against 169 `mbedtls_calloc` sites is blindness, not cleanliness.

`mbedtls_free` *is* caught — but by the `*_free` suffix heuristic
(`ast_utils::is_deallocation_call_name`), not by the alias. That heuristic is
also what produces **47 of the 49 MEM31-C findings: "Double free detected"**
on the destructor idiom

    static void gcm_ctx_free(void *ctx) { mbedtls_gcm_free(ctx); mbedtls_free(ctx); }

where `mbedtls_gcm_free` zeroizes the *members* of `ctx` and frees nothing
(it is in `gcm.c`, inside the `-d` set, so a body-derived summary could say
so). Expect that family to adjudicate as FP. Both are filed as rule follow-ups.

## Adjudication status

None yet. The whole-codebase first pass belongs to `benchmarking_db` (this
repo holds the tool's backlog; labels go to the `sqc_bench` oracle via that
repo's queue). When it is run, gate it on the two MEM follow-ups above per the
delta-adjudication protocol in `CLAUDE.md` — adjudicating 57 findings a
recognised wrapper fix is about to remove is wasted work.
