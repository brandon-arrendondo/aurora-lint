# Changelog

All notable changes to aurora-lint are documented here, for people who use
the tool. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
with three headings per release: **Added** (a new rule, option, output or
capability), **Fixed** (a misfire, crash, wrong result or change in what a
scan reports) and **Removed** (anything you could have depended on that is
gone). Internal work -- benchmarks, adjudication, refactors, CI, docs -- is
not listed; the git history is the archive for that.

**Versions here are published releases**, not every version the crate passed
through. aurora-lint bumps the patch version on nearly every commit, and only
tagged versions are built, signed and published, so a section covers every
change since the previous release. The 0.4.x line shipped from a private
repository and is consolidated here by release, not by patch version.

The `[Unreleased]` section is maintained by `scripts/generate_changelog.py`
from release notes written on the project's task records; the dated sections
are curated by hand. See `docs/adr/0009` for what belongs here and
`docs/adr/0007` for what may never appear here.

## [Unreleased]

_No release notes recorded for this release; see the commit log._

## [0.5.2] - 2026-09-20

### Fixed

- ERR33-C no longer reports a result that is tested in the very condition it is assigned in (`if ((p = malloc(n)) == NULL)`, `if (!(p = f()))`, `while ((c = fgetc(f)) != EOF)`, and as a later operand of `&&`/`||`).
- MEM31-C now sees an allocation returned by a constructor that is defined in a header (`static inline`), and by the callees it returns through, so a leak of that block is reported the same whether the constructor lives in a `.c` or a `.h` file.
- DCL06-C no longer reports a literal that an assertion pins to a named constant expression.
- A scan no longer depends on the order the operating system lists directories in: the same tree gives the same findings however it was copied, archived or checked out, and a name defined in more than one file resolves the same way on every machine.

## [0.5.1] - 2026-09-19

### Fixed

- Findings are now emitted in a fixed order regardless of `--jobs`, so two scans of the same tree export byte-identical files.
- MEM30-C and MEM31-C model control flow more faithfully: a branch that ends in `return`, `goto` or a call that never returns no longer carries its freed or allocated state into the code after the `if`; a loop is left through its `break`s and `continue`s as well as its condition; the `else` arm starts from the state before the `if`. This removes double-free, use-after-free and leak reports that only existed on paths the program cannot take.
- MEM30-C no longer reports use-after-free when the pointer is reassigned from the call's own result (`x = f(x)`), refilled through an out-parameter, or handed as a callback to a registration function; a deallocator is no longer recognised by its name alone when its body shows it frees only fields or nothing; `X_free(obj)` after `X_init(obj)` is not a release of `obj`; and "stack pointer escape" fires only when a global actually takes the address of automatic storage.
- MEM31-C credits a free made in a cleanup label through any callee the pre-scan saw free, cast or not, and an allocator whose result is stored by the callee it links is treated as borrowed rather than leaked.
- INT30-C and INT32-C resolve signed typedef chains, type a compound assignment from both operands, check a 64-bit signed operation against a 64-bit limit rather than `INT_MAX`, and accept a guard in an earlier operand of the same `&&`/`||`. INT30-C no longer reports a `calloc()` product of compile-time constants, or an overflow at a width it cannot determine.
- DCL05-C recognises a pointer typedef by its declaration rather than its spelling and reports the `const` applied to it; it no longer reports every callback parameter, only a declarator returning a pointer to a function.
- DCL06-C no longer reports a literal that an assertion pins to a named quantity, a literal used through `sizeof buf` / `sizeof(x.name)`, or a version check made through an accessor call.
- DCL13-C recognises a write to an array element made through a macro that assigns its parameter.
- ENV01-C reports a `getenv()` value reaching an unbounded copy, not every `PATH_MAX`-sized buffer.
- EXP34-C no longer treats the left operand of `||` as known true at the right operand, which had hidden a possibly-null dereference there.

## [0.5.0] - 2026-09-18

### Added

- `aurora-lint` is published on crates.io: `cargo install aurora-lint`.
- Prebuilt macOS (Apple Silicon) binaries alongside the Linux and Windows builds, `.deb`, `.rpm` and AppImage packages.
- `--report-macro-gaps[=FILE]`: after a scan, report where the macro-expansion engine was blind -- definitions it skipped, `#include`s it could not resolve, calls it could not expand -- as a summary and optionally as JSON. It never changes a finding.
- CON03-C and CON07-C know Zephyr's threads, locks and synchronisation objects, and WIN00-C/WIN02-C/WIN03-C/WIN30-C match the `A`/`W` Win32 entry points, not only the `<windows.h>` macro names.
- Source files that are not UTF-8 are read as ISO-8859-1 instead of being skipped, and Emscripten `EM_ASM`/`EM_JS` bodies are treated as opaque instead of being parsed as C.

### Fixed

- A scan with no `-d` now pre-scans its own target, so a single-directory scan gets the same cross-file context a `-d` scan gets.
- Parsing is more robust: NUL-strewn input (BOM-less UTF-16, binary) no longer stalls the parser; whole declarations, casts and split control-flow headers are recovered from the parser's ERROR nodes; and rules no longer read preprocessor text as C -- an `#ifdef` guard name is not a callee, a `#if` condition is not runtime code, `defined` is not a side effect, and an operator inside a string literal is not an operator (EXP02-C, EXP13-C, INT33-C, PRE31-C, PRE32-C).
- API00-C honours a documented non-NULL precondition on a parameter (a `\param` block saying it must be initialised or non-NULL) as validation placed on the caller, no longer infers a contract from "every visible caller passes non-NULL", and no longer counts an `assert`-only use, a defined unsigned shift or pointer arithmetic as an overflow site.
- MEM30-C and MEM31-C rebuilt their ownership model: a block stored through an out-parameter, field, element or offset has escaped; every alias of a block inherits what happens to it; `p = NULL` ends that name's claim; two different deallocator names on one pointer is teardown, not a double free; a free through a freeing macro, a named wrapper or a `void **` wrapper is credited; a cleanup label reached by `goto` is entered with the state its `goto`s carry; and a free only guessed from a callee's name no longer produces a use-after-free or leak report when the callee's body says otherwise.
- MSC13-C no longer reports a defensive initial value (`int ret = SOME_ERROR_CODE;`, or a literal initializer on the variable the function returns) as a dead store; MSC37-C and MSC07-C treat labels, `case`s and preprocessor arms as control flow, so `goto`-cleanup-then-return and `#if`/`#else`-exhaustive returns are no longer reported.
- EXP43-C judges aliasing by the callee's `restrict`-qualified parameters, not by a call passing one object twice; ARR01-C reads `sizeof(ptr->member)` and `sizeof(*ptr)` correctly instead of as a decayed pointer.
- INT30-C, INT31-C and INT32-C derive parameter provenance from the call graph, recognise overflow guards by dominance rather than spelling, check at the width the arithmetic is performed in, and no longer read pointer arithmetic as integer arithmetic; INT08-C, INT16-C and INT34-C answer from value-range analysis and scope-resolved declarations instead of a fixed width or a name.
- ERR33-C no longer exempts an unchecked `fclose()` in "cleanup context"; it is reported like any other unchecked result.
- EXP02-C, EXP10-C and EXP14-C recognise side-effect-free guards, count only genuinely unsequenced calls, and resolve the operand's declared type; EXP33-C and EXP34-C credit more output-parameter shapes, distinguish MUST from MAY writes, consult the call-site null vote per call, and prove non-nullness from bail-out guards and loop bounds.
- ARR30-C credits a size guard that precedes the access, sizes a subscript against the declaration in scope, and reports the right size, line and `#ifdef` branch; ARR36-C no longer treats a parenthesized expression, a field path, an integer holding an address or the other arm of an `#ifdef` as a distinct array.
- Smaller misfires fixed in DCL06-C (hex/octal literals, value-echo tables, version-macro comparisons), DCL31-C (typedef'd function-pointer parameters, macro-wrapped declarators), FIO47-C (`snprintf` argument positions), INT01-C, MEM03-C, MSC12-C (`volatile` busy-waits, interface stubs, parser misparses), PRE31-C, WIN04-C and WIN05-C.
- Value-range analysis widens `&var` arguments wherever the call sits, applies a `for` loop's own init and update clauses, treats a branch whose condition contradicts its incoming range as dead, and bounds `rand() % n` to `[0, n-1]`.

## [0.4.336] - 2026-09-06

### Added

- The tool is now **aurora-lint**: the crate, the binary, the packages and the man page carry that name. The suppression file `suppress.toml` is unchanged, and the legacy `.sqc-suppress.toml` is still auto-detected.
- `--system-includes`: also search the compiler's own built-in system header directories, found by asking it (`cc -E -Wp,-v -`). Off by default because it spawns a compiler; works with or without `--compile-commands`, which can never contain those paths.
- A man page ships in the crate and the packages, and every package carries the `NOTICE` and third-party licence report.

### Fixed

- MSC04-C reports a deterministic shortest recursion cycle and INT08-C a deterministic variable, so an identical finding no longer changes its message from run to run.
- A single unresolvable system header no longer silently disables DCL31-C for the whole project; DCL31-C recognises function-pointer parameters and locals as declared callables and no longer reads an attribute macro before or after the declarator as a missing type specifier.
- Call-graph and caller-side reasoning cross translation units: ARR30-C reads caller-side index validation and ARR36-C a pointer-parameter pair's caller from another file; a colliding `static` name keeps its call-graph entry and is only marked ambiguous.
- ARR30-C recognises caller-side and loop-condition index validation, treats a terminator test and three more loop shapes as bounding a pointer walk, and attributes a pointer increment to the loop that bounds it; ARR38-C checks the destination's allocation before calling its size unvalidated, credits the concept of a bounds guard rather than one spelling, judges `fread`/`fwrite` struct sizing by declared type, and scopes its size searches to the function.
- ARR36-C tracks a base only for names that can hold a pointer, resolves `typedef struct Tag Alias;` so a member reached through the alias keeps its type, and no longer reads a field path, an untracked pointer's raw name, or one base under two spellings as distinct arrays; ARR00-C no longer reads an ordinary scalar swap as pointer subtraction and follows assignment chains to the pointer's source.
- INT32-C checks arithmetic at its promoted width and only allocation-size arguments; INT08-C's promoted-range premise was inverted, so `char + char` is no longer reported as a possible overflow; INT13-C stops checking a shift's count operand; INT10-C proves guard-bounded signed dividends non-negative and no longer lets a non-negative divisor stand in for a non-negative remainder; INT31-C recognises `float`/`double`/`long double` narrowing to integer types; INT30-C/INT31-C/INT32-C run the provenance gate in every configuration.
- API00-C asks whether a guard reaches the arithmetic rather than how it is spelled, looks for a guard on the parameter rather than guard-shaped text, and recognises `dbus_set_error` as NULL-tolerant; EXP34-C models `NORETURN` calls as terminating control flow and recognises macros that forward to a null-safe function.
- MSC13-C no longer reports declarations split across `#if`/`#else` as unused, sees a use of the caller's variable inside a macro body, looks through a `case` label for declarations, and no longer truncates its dataflow at a flat 1000-iteration cap; MSC17-C no longer takes a bare preprocessor directive as a case's last statement; MSC12-C reports a guard already excluded by the preceding early return.
- MEM31-C recognises a free through a `void **` wrapper's pointee; MEM30-C no longer credits an `#ifdef`-guarded stub's free to a real function's cross-file summary; FIO30-C and FLP03-C merge cross-file macro data instead of collecting per file; DCL13-C skips function-pointer-typed parameters; casts that tree-sitter mis-parses are recognised (INT10-C first).
- Three rules stopped asking every node for its ancestors, and the per-file parent cache is built once, cutting scan time on large files.

## [0.4.315] - 2026-09-01

### Fixed

- Two more quadratic cost sites in value-range analysis, on top of the per-query replay fixed in 0.4.314; large basic blocks no longer make every VRA-consuming rule O(n²).
- EXP33-C recovers its `#ifdef` correlation across a label-and-guard blank; INT14-C no longer collects a call's callee name as a mixed-operation variable; MEM31-C's pointer-evidence guard covers cross-file globals; `if`/`else` chains split across two `#ifdef` guards are reconnected.

## [0.4.314] - 2026-09-01

### Fixed

- Value-range analysis replayed its per-query state in O(n) per call, making any rule that consults it quadratic on large basic blocks.

## [0.4.311] - 2026-09-01

### Added

- Seventeen rules: DCL42-C (unsequenced/reproducible attribute misuse), FLP38-C (type-generic macro floating-type mismatch), MSC00-C (unscoped warning suppression), MSC01-C (logical completeness), MSC05-C (arithmetic on `time_t`), MSC06-C (compiler-optimisable dead stores and spin loops), MSC09-C (non-ASCII bytes in literals), MSC10-C (UTF-8 decoders accepting overlong encodings), MSC11-C (`assert()` used to check allocation results), MSC14-C (`strerror_r` platform dependency), MSC15-C (post-hoc overflow checks that depend on undefined behaviour), MSC17-C (`switch` fallthrough without `break`), MSC20-C (`switch` jumping into a complex block), MSC21-C (fragile loop termination), MSC22-C (`setjmp`/`longjmp` misuse), MSC23-C (text-mode byte counting with `fopen`) and MSC24-C (deprecated or obsolescent functions). 307 rules are implemented; four (ENV04-C, MSC18-C, MSC19-C, MSC25-C) are tracked but disabled by default.
- `--compile-commands FILE`: read include search paths and `-D` macros from a `compile_commands.json`, improving cross-file macro and header coverage for projects that already have a compile database.
- The `requires_manual_review` marker (the `?` confidence flag on the terminal) is now serialised in every export format (JSON, SARIF, CSV, Excel).
- Project-level exceptions the standard itself states: API01-C-EX1 (array of struct), ARR37-C-EX1 (flexible trailing allocation), DCL04-C-EX2 (uninitialised simple multi-declaration), EXP45-C-EX2/EX3, SIG34-C-EX1 (preprocessor-guarded self-signal modification).

### Fixed

- `--rules` now gates which rules run, not only which findings are printed; a scan restricted to a few rules is correspondingly faster.
- Headers that can only be C++ are skipped, so C rules no longer report on `.h` files with C++ constructs.
- About twenty rules kept one whole-file map of variable names and conflated same-named variables across functions (ARR38-C, CON04-C, CON30-C, CON34-C, DCL39-C, EXP39-C, EXP40-C, EXP43-C, FIO01-C, FIO05-C, FIO13-C, FIO24-C, FIO50-C, INT10-C, INT30-C, MEM02-C, POS53-C, STR32-C and others); each now tracks state per function. Identifier resolution is scope-aware throughout: a name resolves to the declaration in scope, not to a matching spelling.
- The control-flow graph models `switch`/`case` (including arms split by `#if`/`#else`), preprocessor conditionals and the dangling-`else`-across-`#if` idiom, and prunes unreachable `case` arms; MSC13-C's dead-store check is rebuilt on it and was unsound across branches, loops and `goto` before.
- Parse recovery: an unknown identifier before a declaration, a locally-defined empty object macro, the `extern "C"` brace idiom and a label immediately followed by `#ifdef` no longer cascade into mis-parsed files; locally-constant `#if defined(MACRO)` dead code is excluded from analysis like `#if 0` already was.
- MEM30-C attributes frees from cross-file summaries rather than callee names, distinguishes MUST-free from MAY-free parameters, and no longer conflates mutually-exclusive `switch` or `#ifdef` arms, a free call's own argument, `goto`-only labels or `realloc` wrappers; MEM31-C clears freed state on reassignment through an allocator wrapper and no longer treats function-`static` pointers, parameter-owned fields, comment-mentioned `malloc()`, list/hash macros or non-pointer-returning callees as leaks or deallocators.
- EXP33-C and EXP34-C recognise cross-file and macro output parameters, field and subscript writes, short-circuit chains, correlated `#ifdef` guards and forwarding macros, exempt static and thread-local storage from uninitialised-read checks, and (with API00-C) no longer accept `assert(ptr != NULL)` alone as validation; EXP34-C recognises SQLite's documented NULL-safe C API.
- Buffer-size resolution shared by ARR00-C, ARR30-C, ARR38-C and STR31-C resolves flexible-array members from the allocation site, `sizeof(T)*N` in either order, nested multiplies, `strlen`-derived and bare `sizeof(T)` sizes, cross-file struct fields, static globals and relay functions; `int64_t` is no longer read as a 4-byte `int`; ARR30-C recognises `recv()`/`read()`-bounded indices, round-up sizing, macro-named bound guards and enum-constant indices.
- INT09-C resolves `#define` and prior-enumerator arithmetic and enumerator aliases in enum initializers instead of defaulting to 0; INT10-C, INT31-C, INT32-C, INT33-C and INT34-C track declared types through comma-list declarators, detect truncation before allocation, follow allocation-size taint one assignment back, and check unsigned right-shift amounts.
- MSC12-C recognises busy-wait polling, documented no-op stubs, attribute-decorated declarations, verification annotations and lock/barrier macros as intentional and no longer reports grouped `case` bodies as empty; MSC17-C recognises fallthrough markers broadly and braced or `if`/`else` terminators; MSC21-C fires only on loops with a constant numeric step; MSC24-C no longer lists `sscanf` as obsolescent.
- MEM33-C resolves types, qualifiers and flexible-array members from the AST rather than identifier names; FLP03-C gates on provenance and knows C23/GCC extended float types; STR02-C tracks call-site-constant strings and knows the SQL sinks (`sqlite3_exec`, `mysql_query`, `mysql_real_query`, `PQexec`); ERR33-C stops suppressing `snprintf`/`vsnprintf` return checks; CON03-C and CON07-C gate on ISR/thread/signal reachability; and smaller misfires were fixed in API02-C, API05-C, CON09-C, CON34-C, DCL06-C, DCL30-C, DCL40-C, DCL41-C, ENV34-C, ERR01-C, EXP30-C, EXP36-C, EXP39-C, EXP42-C, FIO10-C, FIO42-C, FIO47-C, FLP30-C, INT07-C, MEM00-C, MEM03-C, MEM10-C, MEM12-C, PRE00-C, PRE06-C, STR00-C and STR34-C.
- Fixture-driven detection gaps closed in 28 rules (API01-C, ARR37-C, CON07-C, CON09-C, CON34-C, DCL02-C, DCL04-C, DCL07-C, DCL13-C, DCL17-C, DCL37-C, DCL40-C, ENV34-C, ERR33-C, EXP00-C, EXP36-C, EXP42-C, EXP45-C, FIO10-C, FIO34-C, INT09-C, INT34-C, MEM31-C, MSC12-C, MSC13-C, MSC37-C, SIG34-C, STR34-C), and deep nesting no longer overflows the stack in CON34-C/CON40-C.

## [0.4.123] - 2026-07-23

### Added

- `--detect-relevance` with `--write-manifest FILE`: detect categorically inapplicable rule classes (`CON*`, `WIN*`, C11 and Annex K) in the target and `-d` directories and write a relevance-gated manifest, without running an analysis.

### Fixed

- The default rules manifest is embedded at compile time, so a `cargo install` build no longer fails to find it at run time.
- The crates.io package no longer ships internal development and research artifacts, and an unused GUI dependency was dropped.
- Fifteen rules matched raw text spans that included comments and string literals, so a word inside a comment could satisfy or defeat a heuristic (API00-C, ARR00-C, ARR30-C, ARR32-C, ERR32-C, ERR33-C, EXP20-C, EXP33-C, FIO34-C, FLP34-C, FLP36-C, INT30-C, INT32-C, MEM11-C, MEM30-C, MSC40-C, SIG02-C, SIG34-C, STR02-C, STR31-C, WIN03-C); those scans are now structural or run over sanitised text.
- MEM30-C and DCL13-C share a field-sensitive alias/points-to model: a free of `obj->field` is tracked as that field, and a pointer copy is not confused with the object it points to; MEM30-C no longer double-reports a use-after-free on a freed-subscript write.
- MEM31-C recognises macro-wrapped frees, nested field chains, delegating destructors and custom deallocators as ownership transfer, using the macro-expansion engine rather than name heuristics.
- ARR30-C resolves subscript constants through `&var` pointer aliasing; INT32-C's bounded-`for`-loop suppression must actually operate on the loop variable.
- A brace mismatch spanning an `#ifdef` no longer corrupts function boundaries in the call graph, which had attributed one function's calls to its neighbour.

## [0.4.84] - 2026-07-08

### Added

- `--exclude GLOB` (repeatable): exclude files matching a path glob from analysis, e.g. `--exclude '**/onelua.c' --exclude 'testes/**'`.
- `suppress.toml`: one suppression file for both the ignore surface and per-line suppressions, auto-detected in the project root (the legacy `.sqc-suppress.toml` is still read).
- Code under `#if 0` and under `#if defined(__cplusplus)` is excluded from analysis.
- A macro-expansion engine for function-like macros: MEM30-C recognises free-and-null "safe free" macros, EXP33-C recognises macro output arguments, and DCL31-C reads macro-defined declarations, without name matching.
- INT30-C, INT31-C and INT32-C gate on provenance -- they report an operation only when an operand is untrusted or unbounded (a decoder result, a length from input, a value with no range), not on every arithmetic expression. INT32-C reports allocation sizes that wrap a 32-bit `size_t`.

### Fixed

- Stack-overflow and slice-index crashes on large real-world trees; the deep-recursion rules (API00-C, API02-C, DCL01-C, DCL30-C, FIO22-C, FLP03-C, INT30-C, INT32-C, INT33-C, MEM03-C, MSC37-C, PRE13-C, SIG00-C, STR02-C, ARR38-C) were rewritten onto explicit stacks and every rule's AST walk is iterative.
- Duplicate findings: DCL02-C reported one line up to 100 times, POS37-C and SIG31-C reported each finding twice, and FIO42-C reported the same handle as both an unclosed `FILE *` and an unclosed descriptor.
- MEM30-C clears freed state on a fresh declaration, on pointer reassignment and on reassignment to an allocator wrapper, no longer aliases value copies, ignores `realloc` self-assignment on a struct field, treats `goto`/`break`/`continue` as branch terminators, gates union member aliasing on genuine unions, frees only the last operand of free-like calls, and no longer infers a double free across preprocessor conditionals.
- EXP34-C no longer reports a dereference guarded by a precondition `assert`, in a `sizeof`, or on an out-parameter whose call returned success; parameters are seeded non-NULL from `&x` call sites, and error-path null votes are dropped from the seeding.
- STR31-C resolves buffer sizes across functions, through `ALLOCA`, pointer aliases, `memset` content length, indirect `strlen`/`wcslen` `calloc` sizes and parenthesised `malloc` arithmetic; ARR30-C gates string-copy findings on source content length and detects tainted blob-decode loops and parameter-decoder over-reads across functions; FIO30-C tracks format-string taint per function.
- ARR00-C resolves array bounds from the AST declaration rather than a text scan, so braced, designated and `{0}` initializers no longer yield a false out-of-bounds; FLP06-C detects integer arithmetic on the AST and suppresses it when all operands are float; INT33-C skips float division; DCL00-C no longer recommends `const` for a variable modified later in a branch or loop; FIO42-C classifies openers by callee name, not substring; DCL15-C and INT34-C no longer report on single-file analysis or constant shifts; INT34-C proves bitmask-bounded shift amounts safe.
- INT32-C checks 16-bit and `char` operands at their own width, parses char literals, and models `switch` bodies conservatively; value-range analysis narrows the `== false` branch to the non-excluded value.

### Removed

- The interactive terminal UI is no longer in the default build. It is an opt-in Cargo feature: build with `--features tui` to keep `--interactive`.

## [0.4.13] - 2026-06-04

### Added

- Violations are printed to standard output in non-interactive mode, so a plain `sqc PATH` shows results without `--export`.
- Release artifacts include an SBOM.

### Fixed

- A poisoned mutex (a panic on one analysis thread) is recovered from instead of aborting the whole scan; the pre-scan phase runs in parallel; two O(N²) analysis bottlenecks and a missing block limit in value-range analysis were fixed, so large files no longer dominate scan time.
- INT30-C keeps its syntactic fallback when value-range analysis sees a loop-widened overflow and no longer reports single-block false positives; STR31-C's false-positive rate was cut with five targeted fixes; CON33-C and CON07-C reported nearly every candidate and now report only genuine ones; EXP33-C no longer reads array-to-pointer decay as a read or reports constant-function branches and `switch` cases; INT36-C's integer-to-pointer cast check dropped a text match; ARR30-C's index-bounds check consults value-range analysis.

## [0.4.0] - 2026-05-07

First release built and published from GitHub. The tool (then named `sqc`)
shipped with:

### Added

- 283 CERT C rules across the API, ARR, CON, DCL, ENV, ERR, EXP, FIO, FLP, INT, MEM, MSC, POS, PRE, SIG, STR and WIN categories, selected by a TOML manifest (`--manifest`) and per-rule (`--rules`).
- Cross-file analysis: `-d`/`--directories` pre-scans directories for function definitions, `-I`/`--include-path` resolves `#include`s, and `--save-prescan`/`--load-prescan` cache the pre-scan for CI.
- Parallel analysis (`-j`/`--jobs`, auto-detected by default), value-range analysis, control-flow graphs and inter-procedural reasoning behind the INT, ARR, EXP and MEM rules.
- Exports to CSV, Excel, JSON and SARIF 2.1.0 (`--export FILE`, format by extension); CI/CD controls `--fail-on-violation`, `--fail-on-severity`, `--min-severity` and `--diff` (only files changed in git).
- Suppression by inline comment (`// SQC-SUPPRESS: RULE ... JUSTIFICATION: "..."`, generated for a `file:line:rule` by `--generate-suppression`) or by a `.sqc-suppress.toml` file, and an interactive terminal UI (`--interactive`).
- Prebuilt Linux and Windows binaries, `.deb`, `.rpm` and AppImage packages.

[Unreleased]: https://github.com/brandon-arrendondo/aurora-lint/compare/v0.5.2...HEAD
[0.5.2]: https://github.com/brandon-arrendondo/aurora-lint/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/brandon-arrendondo/aurora-lint/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/brandon-arrendondo/aurora-lint/compare/v0.4.336...v0.5.0
[0.4.336]: https://github.com/brandon-arrendondo/aurora-lint/compare/v0.4.315...v0.4.336
[0.4.315]: https://github.com/brandon-arrendondo/aurora-lint/compare/v0.4.314...v0.4.315
[0.4.314]: https://github.com/brandon-arrendondo/aurora-lint/compare/v0.4.311...v0.4.314
[0.4.311]: https://github.com/brandon-arrendondo/aurora-lint/compare/v0.4.123...v0.4.311
[0.4.123]: https://github.com/brandon-arrendondo/aurora-lint/compare/v0.4.84...v0.4.123
[0.4.84]: https://github.com/brandon-arrendondo/aurora-lint/compare/v0.4.13...v0.4.84
[0.4.13]: https://github.com/brandon-arrendondo/aurora-lint/compare/v0.4.0...v0.4.13
[0.4.0]: https://github.com/brandon-arrendondo/aurora-lint/releases/tag/v0.4.0
