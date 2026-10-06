# Real-world corpus scope: what each oracle measures precision over

**Status:** reference. Per-project scope is settled at onboarding and only
changes by a deliberate re-scoping task; this doc is the rationale those
decisions were made with. The machine-readable form is `scope_include` /
`scope_exclude` in `data/benchmark_repos.json`; the scan-side form is the
`--exclude-all` / `--report-exclude` globs and `scan_path` in
`bench/realworld_runner.py`. When
the three disagree, this doc is the one that says *why* — fix the other two to
match it, or revise it here first.

The runner's globs come in two kinds; see
[Scan exclusion](#scan-exclusion-what-the-prescan-reads). The per-project
sections below say `--exclude` where they record an audit as it was run.

Scope says which *files* an oracle measures; `primary_build_config` in the
same JSON says which *build* of them, and every project section below ends
with a `Primary build configuration` subsection giving its rationale. See
[Primary build configuration](#primary-build-configuration-adr-0010)
for what that field does and does not claim.

## Scan exclusion: what the prescan reads

The runner drops each out-of-scope tree from the scan with one of two flags,
and keeps an in-scope file of another configuration out of the prescan with a
third. Which one decides what the files that remain are analysed against:

- **`--exclude-all`** for test, demo and tooling trees that link into nothing
  in scope. Nothing is reported in them, and the cross-file prescan does not
  read them. A test that passes NULL, or a stub that always succeeds, would
  otherwise feed the function summaries and call-site facts the product's own
  code is judged by, and stand in for the definitions the product actually
  links.
- **`--exclude-all`** also for platform port code that is BOTH outside the
  oracle's scored tree AND not built in the configuration of record (the
  project's primary build configuration, below). Such code cannot link into
  the build being evaluated. Platform files inside the scored tree (curl's
  `lib/vtls/schannel.c`, hostap's `src/utils/os_win32.c`) stay in the scan:
  they are in-tree variants of the product, scored under their own
  configuration boundary.
- **`--prescan-exclude`** for those in-tree variants when they lie outside
  the configuration of record (`out_of_config`, below), declared per corpus.
  They are still scanned and reported, and their findings are adjudicated as
  written: an FP there can expose a misconfigured tool setup, and a real
  defect found in one is not suppressed. Only the prescan stops reading them,
  and that includes their own definitions: each such file loses its own
  cross-file context, so what is reported in it can change. The oracle rows
  on those files stay, and their findings are adjudicated as written.
  A one-of-N alternate is another configuration's definition of the same
  function (hostap's empty `os_free` in `os_none.c` beside `os_unix.c`'s
  real one), and a fact that must hold for every definition the call can
  link with would otherwise be decided by a build this oracle does not
  measure (ADR-0010 Decisions 6-7). The oracle rows on those files stay.
- **`--report-exclude`** for code the product compiles in: vendored
  libraries and shared helpers. Nothing is reported in them, but the prescan
  still reads them, because their definitions ARE the ones the product's
  calls reach. Made dark, calls into them lose their declarations and misfire,
  and wrappers they define vanish, which blinds the checks that follow them.

The evidence for each choice is the project's own build files at the pinned
commit: which targets compile which trees. Each project section below has a
*Scan exclusion* subsection naming them. This is a declaration made for the
benchmark, the way any project team declares its own scope; aurora-lint never
infers it. It does not change the oracle scope (`scope_include` /
`scope_exclude`): every tree involved was already unreported.

## Why this doc exists

Each real-world codebase's precision/recall is measured over the **shipped
product**, not the whole checked-out repository: test harnesses, build
tooling, vendored dependencies, language bindings and companion tools are
out of scope, and out-of-scope findings are never labeled. That predicate is
project-specific and was worked out per project, by reading the tree, when
the project's ground-truth oracle was first built.

`CLAUDE.md`'s delta-adjudication protocol requires deriving each project's
in-scope file predicate *before* batching new unlabeled findings — one pass
that skipped it found 63% of its raw dump was out-of-scope noise. That
predicate used to live in `data/precision_audit/<project>/README.md`, which
ADR-0007's 2026-09-16 history purge removed along with everything else under
`data/precision_audit/` (now gitignored working data). Only the raw finding
dumps and per-finding audit narrative were disclosure-sensitive; the scope
sections were methodology, and this file is their tracked home so no clone
or node depends on a locally-regenerated or salvaged copy again.

**What was kept and what was left out.** Each project's *Scope* section is
carried over intact, and *Method* sections are kept where they record an
invocation lesson that changes results (`-I`/`-d` flags, isolated binaries).
Everything per-finding — audit narrative, CVE/candidate-disclosure detail,
adjudication CSVs, batch results — was deliberately excluded, not just
redacted. Salvaged from a pre-purge archive on 2026-09-17.

**Reading the historical bits.** The Method sections describe each audit as
it was run at the time. The binary was then called `sqc` (it is
`aurora-lint` now; the benchmark tool id is still `sqc`, see `CLAUDE.md`),
the runner was `mcp_servers/realworld_server.py` (now
`bench/realworld_runner.py`), and version/commit/count figures are what
that run measured — they are provenance, not current numbers. Task ids
cited inside sections refer to the maintainer's task DB.

## Primary build configuration (ADR-0010)

Scope answers *which files* an oracle measures. It does not answer *which
build* of those files, and until ADR-0010 nothing did. Each corpus's
precision/recall figure is a statement about one configuration —
`primary_build_config` in `data/benchmark_repos.json` is where that
configuration is now written down, and the per-project subsections below are
its rationale.

**It is a declaration, not a filter.** Nothing reads it to drop a finding.
Files listed in `out_of_config` are still scanned, still labeled as written
(ADR-0010 Decision 1), and still counted in the denominator. Adding the field
changed no score. Where a corpus also keeps those files out of the prescan
(`--prescan-exclude`, see [Scan exclusion](#scan-exclusion-what-the-prescan-reads)),
that changes what the in-configuration code is judged against, and what is
reported in the excluded files themselves (they lose their own cross-file
context), but never which files are reported. What it buys is that "this only compiles under X" now has
somewhere to be recorded and counted instead of being re-argued per batch.

**The boundary is platform and architecture only.** A feature or debug flag
*inside* the primary configuration's build — `CONFIG_SAE`, `NDEBUG`,
`CONFIG_TESTING_OPTIONS` — is not a scope boundary; those findings are
labeled on the construct alone, and hostap's ~195 DCL13-C TPs in `CONFIG_*`
`#else` stubs are correct under that rule. Only "this host/architecture never
compiles this file at all" is a denominator question (ADR-0010 Decisions 6–7).

### Why it has to be declared rather than detected

Three different mechanisms take a file out of a build, and only the first is
visible in the file itself:

1. **A whole-file guard with a standard platform macro** — mosquitto's
   `src/service.c` under `#if defined(WIN32) || defined(__CYGWIN__)`, curl's
   `src/tool_doswin.c`. Greppable.
2. **A whole-file guard with a project-specific macro** — sqlite's
   `src/os_win.c` under `#if SQLITE_OS_WIN`. Greppable only once you know the
   project's spelling of "Windows".
3. **Build-system selection, with no guard in the file at all** — seL4's
   CMake picking one `src/arch/` subtree, raylib's `rcore.c` `#include`-ing
   exactly one `platforms/*.c` as source, hostap's `drivers.mak` selecting
   drivers from `defconfig`. **Nothing in the gated file says it is gated.**

Mechanism 3 accounts for the large majority of out-of-configuration files in
this suite (102 of the 108 below). A source-level heuristic finds none of
them, which is the whole argument for a declaration.

### What the field cannot express

It is path-granular. A file the build never compiles is expressible; an
`#ifdef` arm inside a file the build *does* compile is not. An earlier
audit's five INT02-C cases split exactly along that line — `driver_ndis.c`,
`rcore_desktop_win32.c` and `service.c` are whole files and are now declared;
`driver_bsd.c:403`'s `#ifdef WORDS_BIGENDIAN` arm and `build.c:126`'s
`#if SQLITE_MAX_ATTACHED>30` arm are intra-file and stay in the denominator
with no way to mark them. `endianness` and `arch` are declared so an
adjudicator can at least name the axis a row sits on.

### Where each corpus stands

File counts are `.c`/`.h` in scope at the pinned commit (`corpus-check` green
for all twelve when measured), via `bench.corpus.in_scope` — the oracle's own
predicate, not a re-implementation.

| Corpus | Primary configuration | In scope | Outside it | State |
|---|---|---:|---:|---|
| libcrc | `linux-x86_64` | 19 | 0 | clean |
| sqlite | `linux-x86_64` | 214 | 4 | scored |
| mosquitto | `linux-x86_64` | 179 | 1 | scored |
| curl | `linux-x86_64` | 427 | 2 | scored |
| hostap | `linux-x86_64` | 736 | 10 | scored |
| lua | `linux-x86_64` | 60 | 0 | clean |
| raylib | `linux-x86_64` (GLFW) | 23 | 9 | scored |
| pureftpd | `linux-x86_64` | 131 | 0 | clean |
| sel4 | `linux-x86_64-pc99` | 183 | 82 | scored |
| mbedtls | `linux-x86_64` | 174 | 0 | clean |
| valkey | `linux-x86_64` | 234 | 0 | clean |
| ventoy | `windows-x86` | 22 | 0 | clean |

`clean` means scope and configuration agree. `scored` means the
`out_of_config` paths carry labeled ground-truth rows today — an open
denominator gap, listed here so it can be measured, not closed here.
**Closing one is not a mechanical follow-up:** narrowing `scope_exclude` to
match a declaration would drop existing `ground_truth` rows out of the
oracle, which is Brandon's call (and an earlier maintainer note already
warns against piecemeal re-scoping, with a real TP at stake in valkey).

**ventoy is the exception worth reading twice.** ADR-0010 says the
configuration is "POSIX/Linux on the benchmark host for every corpus"; that
is true of eleven. ventoy's `Ventoy2Disk` is a Win32 GUI installer, onboarded
deliberately as the suite's Win32 oracle — it is *scanned* on the Linux host
(with no `-I`, since `windows.h` is not there) but it *measures* Windows
code. The primary configuration is a property of the code being measured, not
of the host running the scanner.

Why ventoy specifically (Brandon, 2026-09-22): the suite had no other heavy
Windows-native codebase, so ventoy was brought in *to be* the Windows
benchmark, not scored as an eleventh POSIX corpus that happens to contain
some Windows code. That is why its primary configuration is windows-x86
rather than defaulting to the POSIX/Linux pattern every other corpus gets by
construction — the choice follows from the reason ventoy is here at all.

## Data model (ADR-0011)

Integer widths are implementation-defined. aurora-lint credits only what ISO
C guarantees (`int` at least 16 bits, `long` at least 32, `CHAR_BIT` at least
8, exact-width types exactly) unless a project declares its target's data
model (`[environment] data_model`, docs/options.rst). Without a declaration a
scan reports what is possible on some conforming implementation, which is
much more than any one target's truth (Brandon, 2026-09-29).

The benchmark corpora are measured on their configuration of record, so each
manifest declares that configuration's data model, as a stated fact about the
code rather than an assumption the tool makes:

| Corpus | Configuration of record | `data_model` |
|---|---|---|
| libcrc, sqlite, mosquitto, curl, hostap, lua, raylib, pureftpd, mbedtls, valkey | `linux-x86_64` | `lp64` |
| sel4 | `linux-x86_64-pc99` | `lp64` |
| ventoy | `windows-x86` (MSVC) | `ilp32`, following `primary_build_config`, and `wchar_t_bits = 16` (MSVC's `wchar_t`; no data model but `llp64` loads it) |

Juliet is declared `lp64` as well (`JULIET_SETTING_OVERRIDES` in
`bench/config.py`): the testcases are built for Linux x86_64 with GCC.

A declared corpus therefore reproduces the widths every earlier run assumed,
except where a proof depended on a width the configuration does not have
(ventoy's `long`, `size_t` and pointers are 32 bits, not 64), or on one the
data model never fixed. `wchar_t` is the second kind: `ilp32` and `lp64` are
Linux and Windows models alike, so they leave `wchar_t` unknown, and only
ventoy, whose Windows build of record has a 16-bit `wchar_t`, declares it.
The Linux corpora do not: where one uses `sizeof(wchar_t)` it is no longer a
constant, and nothing is proven or reported through a guessed size. Declaring moves each corpus's settings
hash, so runs from before and after the declaration carry different run ids.


## sqlite

### Precision scope (what counts as "sqlite")

The oracle measures precision on the **shipped database engine + extensions**,
not the surrounding repository. In-scope vs out-of-scope of the 39,747 findings:

| Scope | Findings | Trees |
|-------|----------|-------|
| **In-scope** | 24,965 (63%) | `src/` core engine, `ext/` shipped extensions (fts3/4/5, rtree, session, …) |
| Out-of-scope | 14,782 (37%) | `autosetup/jimsh0.c` (vendored Jim Tcl), `tool/` (lemon parser-gen, build tools), `test/` (Tcl test glue), plus the test-only and language-binding files inside `src/`/`ext/` — see [Non-engine files](#non-engine-files-language-bindings-and-test-only-code) below |

Out-of-scope code is not labelled; precision is measured over the in-scope
labelled subset. (In a real engagement you audit what you ship and run in
production, not the vendored interpreter or the build tooling.)

#### Non-engine files: language bindings and test-only code

Two categories inside `src/`/`ext/` are excluded even though they sit in the
included trees. Both are enumerated by exact path in
`data/benchmark_repos.json`'s `scope_exclude` — the machine-readable mirror of
this section.

**Language bindings** — `src/tclsqlite.c`/`.h` (Tcl), plus the `ext/jni` and
`ext/wasm` trees. Not the shipped C engine.

**Test-only code.** The `src/test*.c` and `ext/*/test_*.c` globs catch most of
it, but they are keyed on a `test_` *prefix* and upstream does not use one
consistently. Files found and excluded individually because the glob missed
them: `ext/fts5/fts5_test_tok.c`, `ext/fts5/fts5_test_mi.c` (embedded
`_test_`), `ext/fts3/fts3_test.c`, `ext/session/session_speed_test.c`
(`_test` suffix), `ext/fts3/fts3_term.c`, `ext/fts5/fts5_tcl.c`,
`ext/misc/noop.c`, `ext/misc/qpvtab.c`, `ext/misc/randomjson.c`,
`ext/misc/urifuncs.c`, `ext/session/changesetfuzz.c` (a one-time
sweep of the whole `src/`+`ext/` tree, replacing the previous find-one-at-a-
time-during-adjudication pattern).

**The criterion is each file's own stated purpose, never its name.** A file is
excluded only if its own header comment says it is test-only ("only used for
testing", "intended for testing and debugging only", "for testing and
demonstration purposes only", "do not have any practical real-world use"), or
its entire body sits under `#ifdef SQLITE_TEST`, or it is a standalone
`main()` test/fuzz utility rather than library code.

Name patterns are unreliable in *both* directions, which is why the sweep read
headers rather than extending the globs:

- `ext/misc/fuzzer.c` and `ext/misc/amatch.c` read as test tooling and are
  **shipped extensions** (edit-distance virtual tables). In scope.
- `ext/fts5/fts5_tcl.c` has no `test` in its name at all and is **entirely**
  wrapped in `#ifdef SQLITE_TEST`. Out of scope.
- `ext/misc/stmtrand.c`, `explain.c`, `memstat.c`, `csv.c`, `series.c`,
  `stmt.c`, `remember.c` all mention testing or "demonstrates" in their
  headers but describe a real shipped extension. In scope.
- `main.mk`'s `TESTSRC` list is likewise not a criterion: its second block is
  commented "Statically linked extensions" and holds real extensions the test
  shell links, and its first block carries `ext/recover/sqlite3recover.c`,
  `ext/recover/dbdata.c` and `ext/intck/sqlite3intck.c` — shipped extensions
  listed only because their `test_*.c` Tcl wrappers need them. All in scope.

So the exclusion list is enumerated, not pattern-derived. A future sweep should
re-read headers rather than trust either the filename or `TESTSRC`.

### Scan exclusion

Per the rule in [Scan exclusion](#scan-exclusion-what-the-prescan-reads), every tree the runner drops is test, tooling or binding material,
so all of them are `--exclude-all`: `autosetup/` (vendored Jim Tcl, run only by
`configure`), `tool/` (build tools: `main.mk` builds `lemon` from
`tool/lemon.c` as a host program), `test/` and `src/test*.c` (the Tcl test
glue: `main.mk`'s `TESTSRC` list, linked only into `testfixture`), and
`ext/jni/`, `ext/wasm/` (language bindings with their own builds). Two of the
`src/test*.c` files, `test_loadext.c` and `test_sqllog.c`, are not in
`TESTSRC` either; they are test-support sources outside every product build.
The library's objects are `main.mk`'s `LIBOBJS0` list (or the amalgamation),
which names none of these files.

The case that motivated it: `src/test_wsd.c` holds the only body of
`sqlite3_wsd_find`, which `sqlite3GlobalConfig` calls behind the
`SQLITE_OMIT_WSD` arm. Read by the prescan, that test body decided what every
engine call through the macro was proven to do.

The test-only files *inside* `src/` and `ext/` that the oracle excludes by
exact path (see above) are not in the runner's globs, so they are still
scanned and read; only `src/test*.c` is.

### Primary build configuration

`linux-x86_64` — default autoconf build, `SQLITE_OS_UNIX`, compile-time limits
at their defaults.

Four in-scope files are outside it. `src/os_win.c` is wholly inside
`#if SQLITE_OS_WIN` (line 16 through the file's last line) and `src/os_win.h`
is its private header; `ext/misc/windirent.h` is wholly inside
`#if defined(_WIN32) && defined(_MSC_VER)`; `ext/misc/sqlite3_stdio.c` says in
its own first comment that it is a no-op on every platform except Windows.
None is in `scope_exclude`, so all four are scored today.

Not expressible: `src/build.c:126`'s `#if SQLITE_MAX_ATTACHED>30` arm is
intra-file and stays in the denominator. It is also not a platform
axis but a compile-time limit — a third kind of build knob the field does not
model.

### Declared memory functions

`conf/realworld/sqlite-rules.toml` declares `sqlite3_free = 1`. Its body frees
through `sqlite3GlobalConfig.m.xFree`, a function pointer the scan cannot
follow, and the documented API says it releases memory from `sqlite3_malloc`.
Only the root is declared; sqlite's own wrappers free by their bodies. A free
counts only where the scan can show it (a body, a macro, or a declaration), so
without this every `sqlite3_free(p)` would be an escape rather than a free.

## curl

### Scope + file reduction (sqlite lesson)

**`lib/` (libcurl) + `src/` (curl CLI)** — the shipped product.
Excludes `tests/`, `docs/`, `scripts/`, vendored/build tooling, and
**`include/`** (curl's public API headers).

#### Why `include/` is excluded (2026-08-13)

This is *not* a blanket "public headers don't count" policy — mosquitto's
public header (`lib/mosquitto.h`) lives inside `lib/` and stays in-scope
there under the exact same "shipped product" rule. curl's `include/` is only
structurally separate because curl's own repo layout puts its public API in
a dedicated top-level directory instead of alongside the implementation.

The reason it's excluded here is empirical, not architectural: while
delta-adjudicating an earlier INT09-C fix, `include/` turned out to produce
218 findings (measured directly, sqc v0.4.198) dominated by three specific,
*fixable* analyzer gaps rather than a diverse real-bug surface:

- **API02-C** misses the size parameter on multi-line wrapped
  declarations — e.g. `curl_easy_recv(CURL *curl, void *buffer, size_t
  buflen,\n  size_t *n)` gets flagged as missing a size arg even though
  `buflen` is right there on line 2. Also flags genuine single-value
  out-params (`curl_multi_perform`'s `int *running_handles`) that were never
  arrays/buffers to begin with.
- **PRE00-C** flags `typecheck-gcc.h`'s deliberate multi-evaluation
  compile-time type-check macro idiom (`curl_easy_setopt`/`curl_easy_getinfo`)
  as a double-evaluation bug, even though the repeated references are
  side-effect-free and only one branch is ever evaluated
  (`__builtin_choose_expr` semantics).
- **INT09-C** can't resolve `#define`-based bitmask type tags
  (`CURLINFO_STRING + 1`) in enum-initializer arithmetic — the same
  const-eval class that fix addressed for prior-enumerator references, just for
  object-like macros instead. All 67 of curl's post-431-fix INT09-C findings
  are this one root cause.

Until those are fixed, adjudicating `include/` would mostly measure "does
sqc handle these three known gaps," not signal about real bugs. Once fixed,
revisit bringing `include/` into scope — consistent with mosquitto's
precedent — since it would no longer be dominated by known junk.

The realworld-benchmark sqc scan config mirrors this exclusion
(`--report-exclude include/**`), matching the already-scoped cppcheck/clang-tidy
`source_dirs` for curl.

Applying the **sqlite scope lesson** (measure precision on what you ship *and
run* in the benchmark environment): the benchmark host is **Linux**, so files
that are `#ifdef _WIN32`/Apple-only — dead code on this host — are **out of
scope for the Linux oracle**. These are *not* deleted from consideration: they
represent a **distinct Windows/Apple build configuration** that should get its
own audit config later (todo 188; sibling task: bring in Windows open-source
benchmarks). Unlike sqlite's vendored/bindings exclusions, this is a
configuration boundary, not a "don't ship it" boundary.

**Excluded (14 WIN_MAC files, 259 findings):**

    lib/vtls/schannel.c   lib/vtls/schannel.h   lib/vtls/schannel_int.h
    lib/vtls/schannel_verify.c
    lib/vtls/apple.c      lib/vtls/apple.h
    lib/system_win32.c    lib/system_win32.h
    lib/curlx/winapi.c    lib/curlx/winapi.h
    lib/curlx/version_win32.c   lib/curlx/version_win32.h
    lib/curlx/multibyte.c       lib/curlx/multibyte.h

**Kept in scope** (sqlite kept its optional shipped extensions fts/rtree/session,
so curl keeps its cross-platform optional backends): all non-openssl TLS
(`vtls/{gtls,mbedtls,wolfssl,rustls}`), QUIC (`vquic/*`: ngtcp2, quiche), and
SSH (`vssh/*`: libssh, libssh2) backends — cross-platform source that compiles
on Linux.

> The same WIN_MAC exclusion must be applied to the **curl realworld benchmark
> scoring scope** so the dashboard/precision denominator matches this oracle
> (handled the sqlite way: unlabeled out-of-scope files are not scored).

| Scope | Files |
|-------|-------|
| `lib/` + `src/` total c+h | 441 |
| − WIN_MAC (Windows/Apple config) | −14 |
| **In-scope (Linux oracle)** | **427** |
| └ with ≥1 finding | 329 |
| └ 0 findings (FN-read only) | 98 |

### Method (mirrors mosquitto/sqlite/libcrc)

Binary: snapshot of `target/release/sqc` v0.4.35 → `/tmp/sqc-curl-audit-bin`
(isolated so a concurrent rebuild can't corrupt the run). Config-correct
invocation matches the realworld benchmark (curl entry: `-I /usr/include -I
lib`, manifest `conf/realworld/curl-rules.toml`):

```bash
# from the curl checkout
sqc lib -I /usr/include -I lib -d . \
  --manifest .../conf/realworld/curl-rules.toml \
  --export .../curl/curl_lib_0.4.35.json     # 9669 findings
sqc src -I /usr/include -I lib -d . \
  --manifest .../conf/realworld/curl-rules.toml \
  --export .../curl/curl_src_0.4.35.json     # 1789 findings
```

In-scope merged corpus: 11,199 findings, WIN_MAC removed. Per-finding labels
accumulated in a per-project adjudication CSV; imported via `bench
realworld-import-labels` once the benchmark DB was free. Adversarial
re-verification pass per the mosquitto model — re-challenges claimed TPs/FNs
and samples FP buckets, because the adversarial agent consistently surfaces
over-credited TPs, missed FPs, and overlooked FNs.

### Scan exclusion

Per the rule in [Scan exclusion](#scan-exclusion-what-the-prescan-reads): `tests/`, `docs/` (including the `docs/examples/*.c` programs),
`scripts/`, `CMake/` and `projects/` are `--exclude-all`. `CMakeLists.txt`
builds libcurl from `lib/` and the tool from `src/`; `tests/` and
`docs/examples` are separate optional subdirectories (their own
`add_subdirectory`, each building test servers, libtests or example programs
that link libcurl, never the reverse). `projects/` is a different kind: beside
the Windows IDE project files it holds the OS/400 and VMS port glue
(`projects/OS400/os400sys.c`, `ccsidcurl.c`, `projects/vms/*.c`), which only
those platforms' builds compile: `projects/OS400/make-lib.sh` (lines 64-65)
builds `os400sys.c` and `ccsidcurl.c` into libcurl on OS/400 only. That code
adds new entry points (`*_ccsid`, `*_a` variants) rather than replacing the
library's functions; what skews the analysis is its calls into libcurl, whose
arguments feed the call-site facts `lib/` is judged by. It meets the
platform-port criterion in [Scan exclusion](#scan-exclusion-what-the-prescan-reads):
outside the oracle's scored tree and not built in the configuration of record.
`include/` stays `--report-exclude`: the public API headers `lib/` and `src/`
compile against.

### Primary build configuration

`linux-x86_64` — Linux/OpenSSL build. **This corpus is the worked example the
field is modeled on:** the 14 WIN_MAC files above were already pulled out of
`scope_exclude` for exactly this reason, years before there was a name for it.

Declaring it surfaced two in-scope files the curated WIN_MAC list missed, both
Windows-only in their entirety:

- `lib/curlx/fopen.c` — body at lines 41–508 of 508 inside `#ifdef _WIN32`.
- `src/tool_doswin.c` — body at lines 26–910 of 910 inside
  `#if defined(_WIN32) || defined(MSDOS)`.

They are recorded in `out_of_config`, **not** added to `scope_exclude`:
whether curl's Windows boundary should move is a scope decision with labeled
rows behind it, not a typo to fix.

### Declared memory functions

`conf/realworld/curl-rules.toml` declares the two roots `curlx_free` resolves
to: `Curl_cfree` (a global `curl_free_callback`, `free` unless the application
replaces it through `curl_global_init_mem`) and `curl_dbg_free` (the CURLDEBUG
memdebug arm). curl's own wrappers (`curl_free`, `curl_url_cleanup`,
`cf_ctx_free`, ...) are not declared: they free by their bodies once the roots
are known. The TLS backends' documented frees (`BIO_free`, `SSL_free`,
`OSSL_LIB_CTX_free`, the two rustls builder frees) are declared too, after
checking `vtls/`'s `BIO_up_ref`/`X509_STORE_up_ref` sites: each extra reference
goes to `SSL_set0_*bio` or pairs with its own error-path free.

## hostap

### Scope

**`src/` + `wpa_supplicant/` + `hostapd/`** — the shipped
hostapd (AP) and wpa_supplicant (station) daemons and their shared library.
Excludes `tests/`, `wlantest/` (separate test/monitoring tool), `eap_example/`,
`hs20/`, `radius_example/`, `wpaspy/` — none of these ship as part of either
daemon.

| Scope | Files |
|-------|-------|
| Whole-repo .c/.h | 805 |
| − tests/wlantest/eap_example/hs20/radius_example/wpaspy | −69 |
| **In-scope (src+wpa_supplicant+hostapd)** | **736** |
| └ with ≥1 finding | 636 |
| └ 0 findings (FN-read only) | 100 |

Note: at the time of the audit the standing realworld-benchmark `hostap`
entry scanned the **whole repo root** with no `--exclude`, so its dashboard
numbers included the 69 out-of-scope files' ~2,587 findings. Unlike curl's
WIN_MAC split (a build-configuration boundary), hostap's out-of-scope
directories are genuinely non-shipped tooling — the realworld benchmark scan
config should carry an `--exclude` for `tests/**` and `wlantest/**` etc. to
match this oracle's scoring denominator.

### Method (mirrors curl/mosquitto/sqlite)

Binary: sqc v0.4.169 (commit 22c40f2c), fresh run
`sqc-hostap-0.4.169-22c40f2c` via the realworld-benchmark runner, matching
the benchmark's own invocation (manifest `conf/realworld/hostap-rules.toml`,
`-d src -d wpa_supplicant`, `-I /usr/include -I /usr/include/libnl3 -I
/usr/include/dbus-1.0`).

Whole-repo run: 38,659 violations (23 suppressed). Filtered to in-scope
(`src/`, `wpa_supplicant/`, `hostapd/`): **36,072 findings across 636 files**,
174 distinct rules firing.

### Scan exclusion

Per the rule in [Scan exclusion](#scan-exclusion-what-the-prescan-reads): `tests/` (hwsim test scripts, unit-test programs such as
`tests/test-*.c`, and the fuzzing harnesses), `wlantest/`, `eap_example/`,
`hs20/` (the `hs20/client` program), `radius_example/` and `wpaspy/` are
`--exclude-all`. Each has its own `Makefile` building a separate program (or a
Python extension) that pulls in `src/` objects; `wpa_supplicant/Makefile` and
`hostapd/Makefile` list no object from any of them. The fuzzing harnesses'
stub definitions (`tests/fuzzing/*`) are what made this matter: a stub that
always returns a static object stood in for the daemon's own function.

`src/ap/hs20.c` and `wpa_supplicant/hs20_supplicant.c` are the daemons' own
Hotspot 2.0 code and are in scope; only the top-level `hs20/` tree is not.

The ten files outside the primary build configuration (next subsection) are
`--prescan-exclude`: scanned, reported and adjudicated as written, but not
read for cross-file facts, their own included, so findings reported in them
can differ from a scan that reads them. They are the `os_*.c`, `l2_packet_*.c` and driver
alternates that `defconfig` selects one of, so each defines functions the
Linux build takes from its own selection. `os_none.c`'s `os_free` is empty;
read by the prescan, it makes `os_free` a release in only some definitions,
so once a free has to be proven rather than guessed from the name, every
allocation the Linux daemons hand to `os_free` reads as leaked. The
runner's list is checked against `out_of_config` by
`bench/tests/test_out_of_config_prescan.py`.

### Primary build configuration

`linux-x86_64` — `wpa_supplicant` and `hostapd` at their shipped `defconfig`s:
`CONFIG_DRIVER_NL80211`, `WEXT`, `WIRED` and `MACSEC_LINUX` enabled, with
`#CONFIG_DRIVER_BSD=y` and `#CONFIG_DRIVER_NDIS=y` commented out in both.

Ten in-scope files are outside it, and none of them carries a guard saying so —
the selection is one-of-N in `src/drivers/drivers.mak` and the `os_*.c` /
`l2_packet_*.c` sets, driven by `defconfig`:

    src/utils/os_win32.c                 src/drivers/driver_ndis.c
    src/utils/os_none.c                  src/drivers/driver_ndis_.c
    src/l2_packet/l2_packet_winpcap.c    src/drivers/driver_bsd.c
    src/l2_packet/l2_packet_ndis.c       src/drivers/driver_openbsd.c
    src/l2_packet/l2_packet_freebsd.c
    src/l2_packet/l2_packet_none.c

Ten files out of 736 in scope is 1.4% of the file surface, and the finding
density behind it is why it still matters: that earlier audit found 7 of
INT02-C's 46 TP rows in `driver_ndis.c` alone.

`CONFIG_*` feature stubs are **in** this configuration and are labeled on the
construct (ADR-0010 Decision 1) — the ~195 DCL13-C TPs in `CONFIG_SAE` /
`CONFIG_GAS` / `CONFIG_PR` `#else` stubs are correct and are not affected by
anything here. `src/drivers/driver_bsd.c:403`'s `#ifdef WORDS_BIGENDIAN` arm is
intra-file and not expressible; `endianness: little` is declared so the axis at
least has a name.

### Declared memory functions

`conf/realworld/hostap-rules.toml` declares the documented frees of the
libraries hostap links against, whose bodies are outside the scan: OpenSSL
(and wolfSSL through its OpenSSL-compatible names), `wc_PKCS7_Free`, and
libnl's `nlmsg_free`/`nl_socket_free`. `EC_COMP_PUBKEY_free` is generated
in-tree by OpenSSL's `IMPLEMENT_ASN1_FUNCTIONS` and follows the documented
ASN.1 `TYPE_free` contract. hostap takes no `*_up_ref` on these objects; its
one `nlmsg_get` queues a message that a different function frees. `os_free` is
not declared: it has a body and frees by it. `X509_STORE_CTX_cleanup`,
`rtnl_link_delete` and `wpa_driver_ndis_adapter_close` are not frees and are
not declared, although `--report-deallocator-candidates` lists them by name.

## mosquitto

### Scope

**`lib/` (libmosquitto client library) + `src/` (broker
daemon)** — the shipped product. Excludes `deps/` (vendored
picohttpparser), `test/`, `client/`, `apps/`, `plugins/` (example plugins),
`common/`/`libcommon/` (small shared helpers, pulled in only as cross-file
context).

Widened after a later scope audit: `make install` also installs the
public API headers under `include/`, and both `lib/` and `src/` `#include`
them, so they belong in scope too. `config.h` (generated build config,
`#include`d throughout) is in scope for the same reason. The C++ wrapper
headers (`include/mosquitto/libmosquittopp.h`, `include/mosquittopp.h`) are
excluded by name — a language-scope call (sqc is CERT-C only), not an
oversight.

| Scope | Files |
|-------|-------|
| `lib/` | 59 |
| `src/` | 83 |
| `include/` + `config.h` | 37 |
| **Total in-scope** | **179** |

This is a stricter scope than the v0.4.22 sample (which drew from the whole
repo incl. `plugins/` and `test/`); the 15 v0.4.22 mosquitto labels from that
sample include some `plugins/`/`test/` paths that are out-of-scope here and
are not part of this corpus's denominator.

### Method (mirrors libcrc)

Invocation matters (libcrc lesson): scanning `src/` without `-I lib` inflated
DCL31-C from 9 -> 446 (broker headers `logging_mosq.h`, `mosquitto_internal.h`,
`net_mosq.h`, `tls_mosq.h` live in `lib/`, matching the real build's
`-I${R}/lib -I${R}/libcommon` per `src/Makefile`). The config-correct
invocations (from the mosquitto checkout):

```bash
# lib/ (59 files, 714 findings)
sqc lib \
  -I . -I include -I common -I libcommon -I lib \
  -I /usr/include -I /usr/include/cjson \
  -d common -d libcommon \
  --manifest conf/realworld/mosquitto-rules.toml \
  --export .../mosquitto/mosquitto_lib_0.4.30.json

# src/ (83 files, 2672 findings)
sqc src \
  -I . -I include -I common -I libcommon -I lib -I src \
  -I /usr/include -I /usr/include/cjson -I deps/picohttpparser \
  -d common -d libcommon -d lib \
  --manifest conf/realworld/mosquitto-rules.toml \
  --export .../mosquitto/mosquitto_src_0.4.30.json
```

Binary: built from source at Cargo.toml v0.4.30 into an isolated target dir
(`/tmp/sqc-mosquitto-audit`) so as not to disturb `target/release/sqc`, which
another concurrent session used for the sqlite FP-reduction benchmark gate
.

### Scan exclusion

Per the rule in [Scan exclusion](#scan-exclusion-what-the-prescan-reads):
`test/`, `client/` and `apps/` are `--exclude-all`. The top-level
`CMakeLists.txt` adds each as its own subdirectory, building the test suite,
the `mosquitto_pub`/`mosquitto_sub` clients and the auxiliary apps, and none of
them is linked into the library or the broker.

`plugins/` is split. The broker compiles four of its files in:
`plugins/acl-file/acl_check.c`, `acl_parse.c` and
`plugins/password-file/password_check.c`, `password_parse.c` are sources of the
`mosquitto` executable in `src/CMakeLists.txt` and objects in `src/Makefile`'s
`OBJS_EXTERNAL`. So `plugins/**` stays `--report-exclude`, and the plugin trees
the broker does not build in (`dynamic-security/`, `examples/`,
`persist-sqlite/`, `sparkplug-aware/`, each its own loadable plugin) are
`--exclude-all`, which wins for a file both globs match.

`deps/`, `common/` and `libcommon/` stay `--report-exclude`, because the
product compiles them in: `picohttpparser.c` from `deps/` is a source of both
targets (`lib/CMakeLists.txt`, `src/CMakeLists.txt`, and the matching
Makefiles), `uthash.h`/`utlist.h` are included by broker sources,
`common/json_help.c` is a broker source, and `libmosquitto_common` from
`libcommon/` is linked by both the library and the broker. Their definitions
are the ones the product's calls reach: dark, the allocation wrappers in
`libcommon/` vanish and the leak checks go blind.

### Primary build configuration

`linux-x86_64` — default Linux broker and `libmosquitto` build.

One in-scope file is outside it: `src/service.c`, wholly inside
`#if defined(WIN32) || defined(__CYGWIN__)` (the Windows service wrapper). It
is in `src/**` and not excluded, so it is scored today; that earlier audit
found it via INT02-C. Everything else in `lib/`, `src/` and `include/` is portable code
whose Windows handling is intra-file and therefore in-configuration.

### Declared memory functions

`conf/realworld/mosquitto-rules.toml` declares `mosquitto_free = 1`,
libmosquitto_common's documented free (`include/mosquitto/libcommon_memory.h`).
Its definition is in `libcommon/`, outside the scan, and one arm calls
`__libc_free`. Only the root is declared; `db__msg_store_free` and the other
wrappers free by their bodies.

## sel4

### Candidate: seL4 microkernel

[seL4](https://github.com/seL4/seL4) (`@1326364`, cloned 2026-08-20) is a
formally verified microkernel with a public
[C style guide](https://sel4.systems/Contribute/style.html) prohibiting
dead/no-op code; its functional-correctness proof against an Isabelle/HOL
spec is a strong structural argument against *accidental* dead code. Before
onboarding, a literal grep for `if/for/while (...) {}` across the whole
kernel (`src/`, 183 `.c` files, ~50k lines) returned **zero** hits — a much
cleaner signal than curl/mosquitto/hostap's pervasive deliberate no-op
idioms. On that basis it was onboarded as the `sel4` codebase, scoped to
`src/` (the kernel proper; `libsel4/` is the userspace binding library, not
kernel code).

### Primary build configuration

`linux-x86_64-pc99` — `KernelPlatform=pc99 KernelArch=x86`, the configuration
seL4's `compile_commands.json` is generated for (`macro-expansion.md` §11).

**This is the suite's largest denominator gap: 82 of 183 in-scope files (45%)
are never compiled by it.** CMake selects one `arch/` and one `plat/` subtree
and the unselected ones carry no guard at all, so nothing in the source hints
that they are out:

| Out of configuration | Files |
|---|---:|
| `src/arch/arm/**` | 48 |
| `src/arch/riscv/**` | 17 |
| `src/arch/x86/32/**` | 10 |
| `src/plat/{allwinnerA20,am335x,bcm2837,omap3,tk1}/**` | 7 |
| **Total** | **82** |

These are scored today — sel4 holds thousands of labeled rows and they include
`src/arch/arm/**` paths. ADR-0010 Decision 7 names this corpus as the precedent
for its own answer ("seL4 built for x86, arm and riscv is effectively three
codebases in one repository"), so the measurement-side path is onboarding
`sel4-arm` as its own benchmark rather than deleting rows from this one.

**Unverified:** that `pc99` here means x86-64 rather than ia32. `src/arch/x86/32/**`
is listed as out of configuration on that assumption; it was not confirmed
against the generated `gen_config.h`, and it is the one line in this section
that a reader should not take on trust.

## valkey

### Why this codebase

A security-conscious server with genuine pthread concurrency —
`pthread_create` in `src/iothread.c` (I/O threads) and the legacy
`src/threads_mngr.c`, the `ae.c` event loop, `redisAtomic` macros in
`src/atomicvar.h` — so the existing pthread-vocabulary CON* rules apply with
no prerequisite (unlike zephyr, whose `k_thread_*` idiom needs a table entry
first). First scan: CON34-C 411, CON33-C 198, CON03-C 50, CON40-C 37 — the
CON family has real volume here, which no earlier oracle except hostap gave it.

Chosen over Redis for upstream responsiveness, because this project files real
findings upstream and has already paused re-filing against unresponsive
maintainers. Measured 2026-09-09 over the 100 most recent open issues: Valkey
labels ~79% (bug / test-failure / enhancement), Redis ~9%; Redis carries issues
open since 2011 and PRs stale since 2024-03, Valkey's oldest artefacts date to
its 2024-03 founding. License was not the deciding factor. Worth resampling if
a filed Valkey issue goes quiet the way mosquitto's did.

### Candidate

[valkey-io/valkey](https://github.com/valkey-io/valkey) `9.1.2` →
`7f1dffedff6de73058b2c2a389422b6ecd56c8fb` (tag resolved locally to the same
SHA; BSD-3-Clause). Checkout directory `valkey`.

**A stale assumption, corrected before implementing:** the task body warned
that `src/version.h`, `src/commands.def` and `src/fmtargs.h` are
build-generated and absent from a bare clone. At this pin all three are
**tracked** (`git ls-files` lists them), so the bare clone scans without a
build step, no `#include` degrades, and `git ls-files --others --ignored`
finds no `.c`/`.h` for `corpus-check` to flag. Do not build inside the
checkout anyway; there is no need.

`zmalloc`/`zfree`/`zcalloc`/`zrealloc` (`src/zmalloc.h`) are plain functions,
not macros — confirmed; no `macro_expand.rs` work for the allocation rules.

### Scope: the shipped server under `src/`

Machine-readable mirror in `data/benchmark_repos.json`:

    "scope_include": ["src/*.c", "src/*.h", "src/trace/**", "src/modules/lua/**"],
    "scope_exclude": ["src/modules/*.c", "src/unit/**"]

234 in-scope files. The task counted `src/` as 210 files; that is the
top-level `src/*.c` + `src/*.h`. Two first-party subtrees the server build
links are included on top of it:

- `src/trace/` — LTTng tracepoints (`src/Makefile` compiles `trace/*.o` into
  the server; 155 lines).
- `src/modules/lua/` — the EVAL/FCALL Lua scripting engine. It lives under
  `modules/` because Valkey 9 ships it as a built-in module
  (`libvalkeylua.so`, `-DLUA_ENABLED` in `src/Makefile`), but it is the
  scripting attack surface of the server, not a sample: 10 files, 4,055
  lines.

Excluded inside `src/`: `modules/hello*.c` (eight sample modules shipped for
module authors — `helloworld.c`, `helloacl.c`, … — not the server) and
`unit/` (C++ unit tests; never dispatched anyway). `src/commands/` is 426
`.json` codegen specs, nothing to scan. `deps/` (vendored libvalkey,
jemalloc, lua, linenoise, hdr_histogram, fast_float, fpconv, gtest-parallel)
is outside the scan root by construction — same rationale as sqlite excluding
its Tcl bindings — with its headers on `-I` so the types resolve. `tests/` is
Tcl.

Runner entry (`bench/realworld_runner.py`): `scan_path {path}/src`,
`-d {path}/src`, `-I /usr/include` (openssl) + `src` + the six `deps/`
header dirs, `--exclude modules/hello*.c --exclude unit/**`. **`--exclude`
globs resolve relative to the scan root** — verified by probe: with
`--rules API00-C,DCL06-C`, `modules/hello*.c` accounts for 125 findings
without the exclude and 0 with it, `modules/lua` unchanged at 87.

### Manifest: `conf/realworld/valkey-rules.toml`

Full base plus the four suite-wide dead-config disables, and **one
categorical disable: WIN00-05/WIN30-C**, category 1 — Valkey has no Windows
port (`src/Makefile` selects Linux / FreeBSD / Darwin / SunOS / DragonFly; no
file includes `windows.h`/`winsock2.h`). This was not a pre-emptive call: the
exploratory scan with WIN* enabled produced **WIN03-C 36** ("fopen() called
without 'N' flag in mode string") on every POSIX `fopen()` and **WIN04-C 5**
(function pointer stored without `EncodePointer()`), which is a Windows-only
rule describing a defect that cannot occur here, the README's own example of
category 1. Same disposition as libcrc's WIN* block.

`aurora-lint --detect-relevance` reported `threading=true` (genuine) and
`windows=true`, and the latter is a **detector false positive**: its
`WINDOWS_IDENTIFIER_MARKERS` contains `HANDLE`, which matched the comment
`DESIGNED TO HANDLE USER INPUT` at `src/call_reply.c:586`. Filed as a
follow-up (match identifiers, not comment text). Had the detector been right,
`--write-manifest` would have produced this exact disable set itself.

### Scan exclusion

Per the rule in [Scan exclusion](#scan-exclusion-what-the-prescan-reads): `src/modules/hello*.c` (example modules, built by
`src/modules/Makefile` into their own `.so`s) and `src/unit/` (the C++ unit
tests, built only by the `all-with-unit-tests` target into a separate test
binary) are `--exclude-all`. The prescan reads only `-d src`, so nothing
outside `src/` was ever read.

### Primary build configuration

`linux-x86_64` — default Linux server build. Nothing is out of configuration;
there are no platform-alternative sources in `src/*.c` scope.

### Declared memory functions

`conf/realworld/valkey-rules.toml` declares `valkey_free = 1` and
`valkey_realloc = "realloc"`, the names `zmalloc.h` renames `zfree` and
`zrealloc` to. `zfree` moves the pointer back over its size prefix before
freeing it, so no summary shows its argument released, and the jemalloc arms
are under the excluded `deps/`. They are declared as the free and realloc
of blocks from `zmalloc`, which is what their bodies do once the prefix is
accounted for; `zmalloc.h` itself only renames them.

## libcrc

### Oracle polarity (Juliet OMITBAD / OMITGOOD mapping)

In Juliet, the `bad()` function (guarded by `#ifndef OMITBAD`) is code the tool
**should** flag — a true positive; the `good()` function (`#ifndef OMITGOOD`)
is code the tool should **not** flag — any report there is a false positive.
Mapped onto this oracle:

| Juliet            | ground_truth verdict | meaning                                   |
|-------------------|----------------------|-------------------------------------------|
| `good` / OMITGOOD | **FP**               | sqc reported it, but it is not a defect   |
| `bad` / OMITBAD   | **TP**               | a genuine issue sqc should report         |

So the false positives we record are the *good-code* (OMITGOOD) oracle, and the
genuine issues — whether or not sqc currently flags them — are the *bad-code*
(OMITBAD) oracle. The subset of TPs sqc fails to flag are **false negatives**
(recall gaps).

### Method

```bash
# Scan with the project config + include/context flags (a fair CI invocation):
sqc /path/to/libcrc \
    -I  libcrc/include \
    -d  libcrc/src -d libcrc/include \
    --manifest conf/realworld/libcrc-rules.toml \
    --export   .../libcrc/libcrc_cfg_0.4.24.json

python3 -m bench realworld-import-labels \
    .../libcrc/adjudication_libcrc_0.4.24.csv \
    --run sqc-0.4.22-1c94dc95 --source libcrc_full_audit_0.4.24 \
    --adjudicator claude --date 2026-06-11
python3 -m bench realworld-score sqc-0.4.22-1c94dc95        # measured prec/recall
```

**Invocation matters.** Scanning with no `-I` (so `checksum.h` cannot be
resolved) inflated the raw finding count from 422 to 542: DCL31-C alone went
0 -> 44 ("called without prior declaration", all artifacts of the missing
include path) and DCL15-C 1 -> 25. The audit uses the resolved invocation so we
judge the analyzer, not our flags.

**Config = categorical policy; oracle = per-finding truth.**
`conf/realworld/libcrc-rules.toml` (reused by the real-world runner for every
libcrc run) is based on the sibling `d_lib_common` embedded-C policy and only
disables rules that are *categorically* inapplicable to libcrc (Windows-only
rules on a POSIX target; `FIO50-C` separate-function FP; `POS05-C` chroot for
a non-privileged tool; advisory rules the project rejects). It does **not**
suppress the noisy analyzer-misfire rules (FIO47, PRE32, INT36, API00, MEM30,
…): those stay enabled so their false positives are *measured* in the oracle
and motivate fixing the analyzer, rather than being hidden by config.

### Primary build configuration

`linux-x86_64`. Nothing is out of configuration — a portable CRC library with
no platform-alternative sources, and the whole 19-file whole-repo audit scope
compiles here.

## lua

### Scope: 60 in-scope files (33 .c + 27 .h), 31,470 LOC

Flat root source = the shipping interpreter + stdlib + `lua.c` CLI. **Excluded**
(matches the benchmark `--exclude`): `onelua.c` (amalgamation, double-counts
under preprocessing tools), `ltests.c` **and `ltests.h`** (internal test/debug
harness, only built with `-DLUA_USER_H='"ltests.h"'`), `testes/` (C fixtures),
`manual/`.

> NOTE: at the time of the audit the live benchmark `--exclude` dropped
> `ltests.c` but not `ltests.h` (23 findings leaked into the v0.4.59 scan).
> The oracle corpus removes them; `data/benchmark_repos.json` now excludes
> both.

`lualib.h` is the one in-scope file with **zero** sqc findings — still read in
full for FNs.

### Corpus (as audited)

- 3309 sqc findings (3332 raw − 23 `ltests.h`), the reconciliation checklist.
- 16 file-based batches, bin-packed ~1.3–2.4K LOC each, every file carrying
  its sqc findings (empty list = read-for-FN-only).
- Authoritative-review protocol (ground-truth first, sqc as checklist).
- Categorical Lua FP traps worth knowing before adjudicating: longjmp
  errors, `luaM_*` raise-on-OOM, macro-heavy headers, internal cross-TU API,
  portability-not-structural C99.
- An adversarial re-verification pass (FN-refute, TP-refute, FP-hunt).

### Scan exclusion

Per the rule in [Scan exclusion](#scan-exclusion-what-the-prescan-reads): `ltests.c`, `ltests.h` and `testes/` are `--exclude-all`.
`ltests.o` is in the makefile's `CORE_O`, but its whole body is under
`#if defined(LUA_DEBUG)` (`ltests.c`, line 41), which only the test mode turns
on (`TESTS= -DLUA_USER_H='"ltests.h"'`, commented out in the makefile). The
default build compiles it to nothing. Its definitions, a debugging allocator
among them, exist only in the test build.

`onelua.c` stays `--report-exclude`. It is not test material: it
`#include`s every other source to build the product itself as one unit, so
its definitions are the product's own, seen a second time. It is kept out of
the report because its findings would duplicate the sources'. Taking it out
of the cross-file facts as well would be a claim that the one-unit build is
not a build of the product, and nothing supports that.

### Primary build configuration

`linux-x86_64` — default `make linux` build (`LUA_USE_LINUX`).

Nothing is out of configuration. Lua's platform variation is concentrated in
`luaconf.h` as intra-file `#if` arms rather than per-platform source files, so
there is nothing path-expressible to declare — which is a limit of the field
here, not a statement that Lua has no platform-conditional code.

## mbedtls

### Why this codebase

The suite had nine oracles and no dedicated cryptographic library. mbedtls
carries `mbedtls_platform_zeroize`, a real, purpose-fit sensitive-data-clearing
idiom (224 call sites in `library/*.c`) that no earlier codebase offered
MEM03-C — the same "pick a codebase for one rule's first real signal" logic
that brought in pureftpd for CWE-89. The other draw is `mbedtls_calloc` /
`mbedtls_free` (169 allocation sites), which are `#define`d aliases in
`include/mbedtls/platform.h`, a shape none of the nine had at this density.

### Candidate

[Mbed-TLS/mbedtls](https://github.com/Mbed-TLS/mbedtls) `v3.6.7` →
`068ff080b369adfac81509f9b57b2afabaf82dc5` (tag resolved locally to the same
SHA; Apache-2.0 OR GPL-2.0-or-later). Checkout directory `mbedtls`, lowercase,
matching the registry key. The `framework/` submodule is deliberately left
uninitialised — it is test tooling and outside scope. No build step is needed:
`mbedtls_config.h` and `build_info.h` are static checked-in headers, and
`git ls-files --others --ignored` finds no `.c`/`.h`, so there is nothing for
`corpus-check` to flag as contamination.

### Scope: `library/**`

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
lost every cross-file caller).

### Manifest: `conf/realworld/mbedtls-rules.toml`

`aurora-lint --detect-relevance` on `library/` reports `threading=true,
windows=true` — real `MBEDTLS_THREADING_PTHREAD` code in `threading.c` and
`_WIN32`-conditional code in `net_sockets.c`, `entropy_poll.c`, `timing.c`,
`platform_util.c`, not false positives — so no CON*/WIN* gating applies. The
manifest is the full `rules_templates/rules-all.toml` with only the four
suite-wide dead-config disables (ENV04-C, MSC18-C, MSC19-C, MSC25-C), the same
shape as pureftpd and sel4. Threading is opt-in in mbedtls (off by default) but
the code is there and the rules are cheap; per-finding truth is the oracle's
job.

### Primary build configuration

`linux-x86_64` — default `mbedtls_config.h`.

Nothing is out of configuration. Every `library/*.c` in scope is compiled; what
varies is feature gating inside those files (`MBEDTLS_*_C`), which ADR-0010
Decision 1 keeps in the denominator and labeled as written.

## pureftpd

### Scope: the whole daemon (`src/**` + `puredb/**`)

**This section was widened by a later pass (2026-08-25); the original onboarding
scope is preserved below it.** The machine-readable mirror in
`data/benchmark_repos.json` is `"scope_include": ["src/**", "puredb/**"]`.
Those are the only two directories in the pinned tree holding `*.c`/`*.h`
(123 + 8 = 131 files); `gui/`, `pam/`, `man/` and `m4/` contain none, so no
exclude list is needed.

At the time of writing `ground_truth` held 991 labels for `pureftpd@cc28bff5`
across 72 distinct files, and every one of them falls inside that predicate.
Only 6 of those 72 files are the SQL-client files the original audit covered
— the other 66 came from that pass's whole-daemon 10% random sample (573
labels, seed 20260825, source `precision_audit_task551_10pct_sample`) and
from the per-rule delta passes that followed. A follow-up tracks the remaining
~5,021 unlabeled findings.

The declaration was stale rather than the oracle wrong: it encoded the
original six-file onboarding scope below and was never updated when a
later pass widened it. Fixed once the 92%-out-of-scope signal surfaced it.

#### Original onboarding scope: SQL-client files only

Unlike libcrc/raylib/lua (whole-project exhaustive labeling), this audit is
scoped to exactly the two files that motivated onboarding this codebase:
`src/log_mysql.c` + `src/log_pgsql.c` (and their headers `log_mysql.h`,
`log_mysql_p.h`, `log_pgsql.h`, `log_pgsql_p.h`) — the MySQL/PostgreSQL
authentication+logging backends, which call `mysql_real_query`/`PQexec` as
a genuine SQL client. **449 findings**, all 449 adjudicated (full coverage
of this scope). The rest of pure-ftpd (`ftpd.c`, `pure-pw.c`, `ls.c`, etc. —
~5,468 more findings across the whole daemon) is registered and scanned
(so the codebase is in the benchmark suite and its per-rule counts are
tracked), but was **not yet labeled** — same "Partial" tier as
mosquitto/curl/hostap were before their own incremental audits.

No CWE-89-specific rule existed in sqc at the time (that rule didn't
exist yet, gated on this onboarding landing first). So none of these 449 findings are CWE-89
findings; they're the *existing* CERT-C ruleset's findings on real
SQL-client code, which is exactly the ground truth a future CWE-89 rule's
real-world validation needs as its scoped baseline, and useful in its own
right as ordinary CERT-C signal.

### Method

Adjudicated in 4 batches of ~110-113 findings by four independent agents,
each reading the full source files (not just the flagged line) before
judging. Results merged into one adjudication CSV and imported via `bench
realworld-import-labels`.

### Scan exclusion

Per the rule in [Scan exclusion](#scan-exclusion-what-the-prescan-reads): `gui/` is `--exclude-all`. It is the optional GTK admin GUI, a
separate program, and holds no C source at this pin (`Makefile.am` and
`build.sh` only). The prescan reads only `-d src -d puredb`, so the move is a
declaration with no effect on findings.

### Primary build configuration

`linux-x86_64` — default `configure` build.

Nothing is out of configuration. The `bsd-getopt_long.c`, `bsd-glob.c` and
`bsd-realpath.c` portability fallbacks look like a platform boundary and are
not: `src/Makefile.am` lists them unconditionally, so they are compiled on
Linux and are in-configuration.

## raylib

### Scope: raylib's own code only (`src/*.c|*.h` + `src/platforms/*.c`)

**23 files**, and the audit covered all 23 (100% coverage — see the
audit's own final line). The machine-readable mirror in `data/benchmark_repos.json` is:

```json
"scope_include": ["src/*.c", "src/*.h", "src/platforms/*.c"],
"scope_exclude": ["src/external/*"]
```

which resolves at the pinned commit to:

| Pattern             | Files |
|---------------------|------:|
| `src/*.c`           |     7 |
| `src/*.h`           |     6 |
| `src/platforms/*.c` |    10 |
| **Total**           | **23** |

`ground_truth` holds 6,062 labels across 22 of these; the 23rd
(`src/config.h`) is in scope but produced no findings.

**Why the `scope_exclude` is not optional.** `bench/corpus.py:in_scope`
matches with `fnmatch`, where `*` crosses `/`. Without the exclude,
`src/*.c` alone also matches `src/external/glfw/src/init.c` and the rest of
the bundled third-party tree, giving **121** files instead of 23. The
exclude is written so that a consumer re-implementing the predicate with
true recursive-glob semantics (`*` stopping at `/`) still lands on 23 — it
is a no-op under the stricter reading and load-bearing under fnmatch.

**What is deliberately out of scope**, and was never audited:

- `src/external/` — 98 files of vendored third-party code (miniaudio, GLFW,
  stb, RGFW, cgltf, tinyobj, m3d). Not raylib's code. The split is
  meaningful rather than merely conventional: raylib's own loaders and the
  vendored parsers it delegates to for other formats validate their input
  to different standards, so a finding's disposition depends on which side
  of that boundary it sits.
- `examples/` — ~230 standalone demo programs, not library code.

Sweeping either in would multiply the coverage denominator by ~16 against a
labeled corpus that never touched them.

### Scan exclusion

Per the rule in [Scan exclusion](#scan-exclusion-what-the-prescan-reads): `examples/`, `projects/` and `tools/` are `--exclude-all`. raylib is
the one corpus whose scan path (`src/`) is narrower than its prescan: the
runner adds `-d {path}` for the whole checkout, so without a declaration
the prescan read these demo programs. `examples/` (every file has its own
`main()`) is built only under `BUILD_EXAMPLES` as its own
`add_subdirectory`; `projects/` holds IDE and template starter projects; and
`tools/` holds two standalone programs (`rexm`, `rlparser`). None is linked
into the library (`add_subdirectory(src raylib)`).

`src/external/` stays `--report-exclude`: the library compiles it in, through
`src/rglfw.c`'s `#include` of the GLFW sources and the single-header libraries
implemented inside raylib's own translation units.

### Primary build configuration

`linux-x86_64`, `PLATFORM_DESKTOP_GLFW` — raylib's default desktop backend.

Nine of the ten `src/platforms/*.c` are outside it, which is 39% of this
corpus's 23 in-scope files — the highest proportion in the suite after sel4.
The mechanism is unusual and worth stating: `src/rcore.c` `#include`s exactly
one platform file **as source**, in an `#if defined(PLATFORM_*)` chain at lines
515–530. The gate lives in the *including* file, so the nine unselected
backends contain no preprocessor guard of their own and no amount of reading
them reveals that they are not built.

    rcore_android.c        rcore_desktop_rgfw.c   rcore_desktop_sdl.c
    rcore_desktop_win32.c  rcore_drm.c            rcore_memory.c
    rcore_template.c       rcore_web.c            rcore_web_emscripten.c

They are scored today: the first `ground_truth` row this project returns is a
TP in `src/platforms/rcore_android.c`. Onboarding raylib's platform
backends as their own configurations is the measurement-side path.

## ventoy

### Scope: the installer's own top-level sources only

`Ventoy2Disk/Ventoy2Disk/*.c` and `*.h` — **22 files** (16 `.c`, 6 `.h`,
~14.7K lines): the Windows GUI installer plus its `ventoy_cli.c` CLI. It is
first-party C, not C++: COM (VDS, WMI) is driven through the classic
C-style `lpVtbl->Method(...)` vtable idiom. The machine-readable mirror in
`data/benchmark_repos.json` is:

```json
"scope_include": ["Ventoy2Disk/Ventoy2Disk/*.c", "Ventoy2Disk/Ventoy2Disk/*.h"],
"scope_exclude": [
  "Ventoy2Disk/Ventoy2Disk/fat_io_lib/**",
  "Ventoy2Disk/Ventoy2Disk/ff14/**",
  "Ventoy2Disk/Ventoy2Disk/xz-embedded-20130513/**"
]
```

Under path-aware globbing `*` stops at `/`, so the include alone already
yields the 22 files; the exclude states the intent (the same reason raylib
keeps its `src/external/*` exclude) and names the three vendored
subdirectories the runner drops with `--report-exclude`:

| Directory                 | What it is                              | Licence       | `.c`/`.h` |
|---------------------------|-----------------------------------------|---------------|----------:|
| `fat_io_lib/`             | Ultra-Embedded FAT library              | GPL           | 20        |
| `ff14/`                   | ChaN's FatFs R0.14                      | permissive    | 7         |
| `xz-embedded-20130513/`   | XZ Embedded decompressor                | public domain | 18        |

They stay in the `-d` prescan so the headers the installer includes from
them (`ff.h`, `fat_filelib.h`, `xz.h`) resolve; they are excluded from
*reporting* because they are not Ventoy's code and carry different
provenance.

**Non-scope**: everything else in the repository — `GRUB2/`, `IPXE/`,
`BUSYBOX/`, `EDK2/`, `ExFAT/`, `LinuxGUI/`, `Plugson/`, `VtoyTool/`, the
`vtoy*` Linux tools and the shell/Python tooling. Linux, GRUB, firmware and
build-system code, none of it relevant to a CERT-C scan of the installer.
`Vlnk/src/main_windows.c` (+ shared `crc32.c`/`vlnk.c`, ~890 lines) is a
second, smaller genuine Win32 C tool in the same repo, deferred as a
separate low-priority follow-up: low marginal value next to Ventoy2Disk's
surface.

### Scan exclusion

Per the rule in [Scan exclusion](#scan-exclusion-what-the-prescan-reads), nothing here moves. The three vendored libraries are `ClCompile`
items of `Ventoy2Disk.vcxproj`, so they are part of the installer and stay
`--report-exclude`. Dark, calls into them would lose their declarations and
misfire. The prescan reads only `-d Ventoy2Disk/Ventoy2Disk`, so the rest of
the checkout (GRUB2, LinuxGUI, and the other programs) was never read.

### Primary build configuration

`windows-x86` — **the one corpus in this suite that is not a Linux oracle.**

`Ventoy2Disk` is a Win32 GUI installer driving COM (VDS, WMI) through the
C-style `lpVtbl->` vtable idiom. It is *scanned* on the Linux benchmark host —
with no `-I` at all, since `windows.h` and the COM headers are not there and
aurora-lint parses without them — but what it *measures* is Windows code. It
was onboarded deliberately as the suite's Win32 oracle rather than having
Windows code scored under a Linux one (ADR-0010 Decision 7).

Nothing is out of configuration: the entire 22-file scope is the Win32 build.

Read ADR-0010's "today it is POSIX/Linux on the benchmark host for every
corpus" as true of the other eleven. The primary configuration is a property of
the code being measured, not of the host running the scanner.
