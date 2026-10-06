# Changelog

All notable changes to aurora-lint are documented here, for people who use
the tool. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
with four headings per release: **Added** (a new rule, option, output or
capability), **Changed** (a change in what existing output or options mean),
**Fixed** (a misfire, crash, wrong result or change in what a scan reports)
and **Removed** (anything you could have depended on that is gone).
Internal work -- benchmarks, adjudication, refactors, CI, docs -- is not
listed; the git history is the archive for that.

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

## [0.6.0] - 2026-10-05

### Added

- Policy and environment settings. `--profile default|strict` (or `profile` in the manifest) picks a preset, and `--policy default|strict`, `--environment hosted|freestanding`, `--libc` (iso-posix, glibc, musl, newlib, picolibc, custom) and a repeatable `--set NAME=VALUE`, or the manifest's `[policy]` and `[environment]` tables, override it option by option. The default preset is the default policy on a hosted environment; strict is the strict policy on a freestanding environment with no libc model, for teams that trust nothing a build or platform could take away (an assert that NDEBUG strips, `_Noreturn`, free(NULL) being a no-op, the standard library's exit functions). `--list-options` shows every option under each preset and the current settings, and a SARIF report records the resolved settings and their hash.
- ERR33-C now checks the result of every function in CERT C's table of standard library error returns, including getc, getchar, putc, setvbuf, the wide-character input/output and conversion functions, the search functions, the C11 threads functions and the Annex K functions, each against the error return CERT gives for it. Results that CERT's exception EX1 says need not be checked (puts, putchar and their wide counterparts, and wide output to stdout or stderr) are still not reported.
- `[environment.allocators]` / `[environment.deallocators]` in the manifest, and `--allocator NAME[=CONTRACT]` / `--deallocator NAME[=ARG]` on the command line, declare memory functions the scan has no body for. A declared deallocator frees the argument it names, and a declared allocator follows the named standard allocator's contract. The memory-lifetime rules read the declarations. A manifest's declarations also apply under `--profile`, and they enter the settings hash only when set.
- New `--exclude-all` leaves matching files out of everything: they are not scanned, nothing is reported in them, and their definitions no longer feed the cross-file facts other files are checked against, so a test stub or example program no longer stands for the real function. New `--report-exclude` silences code you still want read (vendored code your product links), and `--prescan-exclude` reports files without reading them for cross-file facts; a manifest's `[scope]` table takes the same three lists as `exclude_all`, `report_exclude` and `prescan_exclude`. `--exclude` is deprecated: it keeps its old meaning, the same as `--report-exclude`, so existing command lines give the same findings, and it prints a warning naming the replacements.
- Each release's documentation is now published at https://brandon-arrendondo.github.io/aurora-lint/<tag>/ and kept unchanged, so a page can be cited as it read at that release; versions.html at the site root lists every release.
- A `data_model` (iso, ilp32, lp64, llp64) is a named bundle of integer facts, and `[environment]` can override each one by key: char_bits, short_bits, int_bits, long_bits, long_long_bits, pointer_bits, wchar_t_bits, char_signed, float_bytes, double_bytes, long_double_bytes, time_t_bytes, off_t_bytes (also via --set). A width must be a whole number of 8-bit bytes, up to 64 bits, so a `char_bits` of 9 or 12 is refused; values below the ISO minimum or out of rank order are refused too, with the key named. Declared facts are part of the settings hash.
- `--list-options` shows every integer fact with its source (cli, config, data-model:NAME, iso-floor, unknown); `--check-config` validates the manifest and command line exactly as a scan would, without scanning; `--write-config FILE` writes a complete commented configuration (refuses to overwrite without --overwrite; `-` prints to stdout).

### Changed

- Under the default preset, a function declared only with GNU's `__attribute__((noreturn))`, or with a `NORETURN` macro that expands to it, no longer ends a path unless its body is seen never to return. ISO C's `_Noreturn`, `<stdnoreturn.h>`'s `noreturn` and `[[noreturn]]` still do, as do POSIX `_exit()` and a wrapper whose body ends in it.
- API00-C no longer asks `main` to validate `argv` in a hosted environment (the default preset), since C guarantees it is a valid array there; under the strict preset `main` is checked like any other function.
- aurora-lint now refuses a manifest with an unknown top-level key or table, so a misspelled table can no longer leave a scan on default settings, and refuses a saved prescan cache written by a different version, with a message to re-create it, instead of misreading it.
- MEM06-C now reports only memory that holds a credential (a buffer that reaches a password or passphrase argument of LogonUser, crypt, PAM, a database or LDAP login, or a password-hashing call) and is not locked into RAM before the secret is stored in it; it no longer reports every allocation. It does not yet follow a buffer through pointer aliases, unions, function pointers, globals or across files, so those cases are not reported.
- PRE31-C now judges every preprocessor arm of an unsafe macro, including variadic arms and arms that only stringize an argument, and counts each use of an argument separately (sizeof/typeof/_Generic operands are not evaluations). Among library macros only assert's argument and the stream argument of getc/putc/getwc/putwc are checked. A call in the argument is reported when the callee is shown to have a side effect. An unproven call (no definition in the scan, a call through a pointer, a function another scanned file defines that nothing yet proves pure or impure, or a library function whose only effect is overwriting its own static result, such as strerror, inet_ntoa, strsignal, gai_strerror, getenv, gmtime or asctime) is reported only under the strict preset: new option pre31_unknown_call_pure and environment contract stdlib_call_effects. New options change the settings hash, so run ids recorded from this release carry a new hash.
- PRE05-C no longer reports a macro argument whose parameter the same macro definition also uses plainly (such as `assert(expr)`, which evaluates `expr` as well as stringizing it), or one passed through GNU's `, ##__VA_ARGS__`, since those arguments are still macro-expanded.
- ERR33-C applies CERT's exception ERR33-C-EX1 exactly as written. printf, vprintf, puts and putchar results may still be discarded; fprintf, vfprintf, fputs and fputc results may be discarded only when the stream is stdout or stderr, named directly or through a macro alias. Writing to any other stream without checking the result is now reported, and so is a discarded sprintf or vsprintf result. A stored result is also judged more precisely: a read through it before its test is a use, EOF must be tested as EOF, a loop condition counts for a read at the bottom of the loop, and a test inside a macro counts only when every definition of the macro makes it.
- ERR33-C findings now quote the function's error return as CERT's table states it. A `function_prefix` waiver is also matched against identifiers in that quoted text, so a waiver such as `function_prefix = "thrd_"` now also hides findings for functions whose quoted error return names a `thrd_` value (for example `mtx_*`, `cnd_*` and `tss_*`, which return `thrd_error`).
- aurora-lint now refuses an invalid suppression file instead of loading only part of it. An unknown table (such as [[suppression]] or [[wildcard]]), an unknown key (such as `reason` for `justification`), an entry with no `name`, a `hash` entry without `file` and `rule`, or an entry with nothing to match on is reported, all problems at once, and a suppression file that cannot be read or parsed stops the run with exit status 2 instead of a warning.
- MEM30-C, MEM31-C and the other memory rules count a call as freeing its argument only where the scan can prove it: from the callee's body, a macro expansion, the C library contract, or a deallocator the project declares (`[environment.deallocators]`, `--deallocator`). A callee's name alone (`*_free`, `destroy_*`, `*_cleanup` and the like) no longer counts, so a bodiless library free now leaves its argument reported as leaked until it is declared; `--report-deallocator-candidates` lists the undeclared callees that would change a finding. A callee that releases its argument on some paths only still clears a leak but no longer supports a double-free report.
- EXP34-C no longer treats a documented "must not be NULL" parameter comment, or a sqlite API's name, as proof that a pointer is non-null; such dereferences are now reported (API00-C likewise no longer credits documentation).
- Without a declared data model only what ISO C guarantees about integer widths is credited: nothing is proven or reported through a guessed width, and a defect that occurs at some conforming width is reported. Under this default, constant expressions that overflow a 16-bit int (e.g. `1024 * 1024`) are reported in assignments and arithmetic operands; declaring a data model or `int_bits` clears them. An integer constant too wide for a 16-bit int is taken to be at least 32 bits wide (int on most targets, long otherwise); an implementation with an int between 17 and 31 bits is not modelled, so declare `int_bits` for such a target.
- CHAR_MAX and CHAR_MIN are unknown unless `char_signed` is declared and CHAR_BIT is known (a data model or `char_bits`), and a proof through one is lost; no data model sets `char_signed`, and only the Windows-only `llp64` sets `wchar_t_bits`. The buffer-size checks of ARR30-C, ARR38-C and STR31-C do not follow the data model yet.

### Fixed

- FIO47-C no longer reports an invalid conversion specifier at the seam between adjacent string literals in a format string (such as "0x%04" PRIX16 "\n"); literal-only joins are validated as the single string the compiler sees.
- FIO47-C now takes an argument's type from its actual declaration, so it no longer reports a type mismatch for an integer declared on a line that also declares a pointer, one initialised with a multiplication, one whose declaration carries an attribute macro such as UNUSED, or one whose name merely contains "int".
- FIO47-C's type-mismatch message now quotes the format directive as written (for example '%-20lx' rather than '%x'), and names which part of a '%.*s' directive a mismatched argument belongs to.
- FIO47-C no longer miscounts arguments for a '*' field width or precision: in printf-family calls ("%.*s", "%*d") the '*' consumes an int of its own, and in scanf-family calls an assignment-suppressing "%*d" consumes none.
- FIO47-C no longer reports a scanf scanset such as `%[^\n]` or `%128[^"]` as an invalid conversion specifier, and no longer misreads the characters inside the set as further format directives.
- EXP19-C no longer reports a braced `else` body as unbraced when a comment sits between `else` and the body, and MSC01-C follows an if/else-if chain across comments and `#if`/`#endif` lines instead of judging each fragment separately.
- FIO30-C again reports format strings that reach a file-scoped `static` sink through a forwarding static, a local source function's return value or a static global, and follows calls made through a local function pointer.
- EXP34-C no longer reports a pointer as possibly null after a guard that assigns it inside the test, such as `if ((p = malloc(n)) == NULL) return;` or `while ((node = next(it)) != NULL)`.
- EXP33-C no longer reports reads of `static` or `_Thread_local` variables that have no initializer; C zero-initializes them, so their value is never indeterminate.
- ENV30-C no longer attributes a getenv()/strerror()-style origin to a different variable that shares a name, or to a buffer that only copied the returned text.
- MEM10-C no longer reports `sizeof(x)` as a pointer's size when `x` is a scalar, a local array, a pointer whose own bytes are being copied, or an element of an array of pointers.
- EXP33-C no longer reports `extern` declarations, array names used only as addresses (`p != buf`), buffers filled through a pointer passed by name, or variables read outside the block that declared them; and `#if __has_include(<header>)` no longer corrupts the parse of the code after it.
- MEM31-C no longer reports an array whose elements are allocated in a loop as leaked when the array is owned elsewhere: returned to the caller, stored in a field, parameter, global or static, or released by a deallocator call or unwind loop rather than a matching free loop.
- EXP34-C no longer reports a dereference guarded by an assert-style macro that no build configuration compiles out, such as one that calls abort() or exit() when its condition is false. Macros with an NDEBUG arm, and checks switched on at run time, still guard nothing.
- FIO05-C output is deterministic, and it no longer reports a reopen when the two opens sit in opposite arms of an if, or when a reused handle's close was filed under the wrong file.
- EXP34-C no longer reports a pointer argument as null when it was reassigned (for example from a function call) after being set to NULL, and it now recognizes an allocation checked with exit() or abort() as non-null.
- EXP19-C no longer reports an if/else body written as a macro invocation with no semicolon whose expansion is a braced block, nor the `} while (0)` that closes a do-while inside a multi-line #define containing a comment.
- Rules no longer take what a function's visible callers pass as proof about its parameters unless every caller is in the scanned source (the function is `static` and its address never escapes). Exported functions, library entry points and callbacks are now checked on their own bodies for value ranges, buffer sizes, taint and index validation, and count as possible concurrent entry points for CON03-C and CON07-C. DCL19-C no longer reports a function that another scanned file calls.
- STR38-C output is deterministic and each call is reported at most once. It takes a string argument's narrow or wide character type from that argument's own declaration, a string literal's prefix or a cast, so a variable whose name contains, or matches, another variable's name no longer decides it, and an argument whose type it cannot resolve is not reported. EXP30-C and POS53-C now name the variables and mutexes in a finding in a fixed order.
- EXP34-C no longer reports a dereference in a later operand of a condition such as `p == NULL || x || p->field`, which is reached only when `p` is non-null, and no longer takes `if (p == NULL && x) return;` as proof that `p` is non-null afterwards.
- Code inside an assert's argument is now checked: EXP34-C reports a dereference of a possibly-null pointer written in an assert, API00-C reports overflowing arithmetic there, and an assert no longer guards a dereference inside its own condition. A plain assert still guards the code after it under the default preset (EXP34-C, ARR38-C, INT33-C, FLP36-C); under the strict preset, which reads the release build where NDEBUG removes it, it does not.
- ERR33-C now credits a check only when the variable that holds a function's result is itself tested against that function's error value (NULL, EOF, a negative or short count, (T)-1, SIG_ERR, or errno/end pointer for strto*), anywhere later in the function before the variable is overwritten. The heuristics it replaces are gone: text matching over the next five statements (where `!s` counted as a test of `sz`), the error-handling-context and "stderr"-in-nearby-text exemptions, credit from assert(), and the requirement that a strto* end pointer be named `endptr`.
- The signal- and exit-handler rules (SIG00-C, SIG01-C, SIG30-C, SIG31-C, SIG34-C, SIG35-C, ERR32-C, ENV32-C) and CON03-C/CON07-C's reachability now find handlers by what is registered rather than by function name or signature. Handlers installed with sigaction() (sa_handler or sa_sigaction, by assignment or designated initializer), through a local registration wrapper or macro, or by address (&f) are now checked. Functions that merely look like handlers, and signal() calls that ignore a signal or restore a saved disposition, are no longer reported.
- Signal-handler rules (SIG00-C, SIG01-C, SIG30-C, SIG34-C, SIG35-C) now recognize handlers declared only in a header, handlers installed through a local function pointer, a file-scope `struct sigaction` initializer or a wrapper that registers several signals, and (with `-d`) a handler registered in one file but defined in another.
- MEM06-C: a lock or core-dump limit is credited only where it holds in every build configuration and on every path to the store (short-circuit and ?: branches, goto paths, #ifdef arms); more store forms are recognized (Annex K _s copies, ReadFile, getline, *p++ =), and a project function locking memory or protecting the process in every definition is credited.
- SIG30-C no longer reports a function-like macro called in a signal handler as an unsafe call: it checks what the macro expands to in every #if branch (so `UNUSED(sig)` is quiet, and a macro that calls `fprintf()` in any configuration is reported as calling `fprintf()`), and each message names the macro the call went through.
- A compile_commands.json written for an MSVC build (cl.exe or clang-cl, including behind sccache or ccache) is now read with cl's own syntax. /D, /U, /I, /imsvc, /external:I and /FI now apply to the scan; before, they were silently ignored. @file response files (UTF-8 or UTF-16) and Windows command-line quoting are handled too. cl takes its SDK and CRT include directories from the environment rather than the command line, so pass those with -I.
- PRE00-C, PRE01-C, PRE02-C, PRE05-C, PRE12-C and PRE32-C no longer read operators, parameters or directives inside string and character literals or comments in a macro definition as code; PRE02-C also reports operators written without spaces and no longer reports a replacement list that is a single call or subscript; DCL16-C and DCL18-C now check the number literals inside #define replacement lists.
- Macros, aliases and functions defined differently under #if/#ifdef are now checked in every build: a free, write, clear or null that would remove a finding must happen in every definition, one that starts a finding counts if any definition has it, a function counts as never returning only if every definition ends the process, and a macro argument that one build ignores is reported at its next use instead of at the macro call. File-scope statics are constant-folded only when nothing writes them and they have one value in every configuration, and a branch is pruned as dead only on a constant fixed in every configuration.
- FIO30-C no longer reports a format string that is a conditional expression (cond ? "a" : "b", parenthesized or not) whose two result operands are both string literals; a non-literal operand is still judged on its own.
- EXP47-C reports each va_arg that reads a promoting type (char, short or float, in any specifier order, through __builtin_va_arg, or in a macro body) exactly once, and no longer reports va_arg(ap, char *) or a va_arg written in a comment or string.
- Windows projects scanned with a compile database from cl or clang-cl now find headers the way the Windows build does, ignoring case in #include names (for example <Shlobj.h> finds ShlObj.h). --include-names exact|case-insensitive, or include_names in the manifest's [environment] table, overrides this. --report-macro-gaps lists each include spelled in a different case from its file, and each name that matches several files differing only in case. Settings hashes are unchanged unless --compile-commands names a cl or clang-cl build, or include_names is set to case-insensitive.
- A static constant that is defined differently across #if, #elif or #elifdef arms, or only tentatively in one arm, is no longer folded to a single value, so EXP33-C and FIO30-C no longer skip code that one of those builds compiles; definitions inside #if 0 are ignored.
- PRE31-C no longer reports an argument with side effects passed to a C library function the implementation defines as a macro (such as `tolower`), since C11 7.1.4 requires such a macro to evaluate each argument exactly once. The standard's own exceptions, the stream argument of `getc` and `putc`, are still reported. Set `library_macros_evaluate_once=false` to judge those macros by their definitions. A project macro defined differently in two headers is judged by the definition its file's includes reach.
- The suppression documentation and man page described [[suppression]] and [[wildcard]] tables that aurora-lint never read, so a file written from them suppressed nothing; they now describe the [[suppress]] entries it does read.
- PRE31-C now judges a function called in a macro argument by what its body does, across every scanned file. A call to a function proven to change nothing is no longer reported. A call to one proven to modify an object outside itself is now reported under the default profile too, where before it was reported only under strict. A call the analysis cannot follow keeps the profile's policy, reported under strict only. A call pasted onto a prefix with `##` (`prefix_ ## CALL`) is now judged by the function the paste produces, instead of as an argument that is never evaluated.
- FIO30-C no longer reports a comment inside a call's argument list, a cast string literal, or a parenthesized or cast format parameter forwarded to a vprintf-family function as a user-controlled format string.
- A function that frees its parameter moved by a constant (`free((T *)p - 1)`, or through a local `h = (T *)p - 1; free(h)`), or through a local copy of it, is now recognized as freeing that parameter.
- A leak, an uncleared buffer or an unclosed file is no longer excused because the called function releases, clears or closes it in only some of its definitions (in different #if branches or files); every definition the call can link with must do it (MEM31-C, MEM03-C, MEM30-C, FIO42-C).
- Code where an #if/#else supplies alternative parts of one condition (each arm one operand of an `if (...)`, or each arm opening the same `if` with its own brace) now parses: aurora-lint keeps the arm the scan's configuration compiles, and leaves the code unrepaired when it cannot decide (a version comparison against an undeclared macro, a compiler-reserved macro the configuration does not set). Findings in a file that such a conditional had turned into one parse error are now reported, and findings that read the wrong arm are gone.
- EXP34-C now reports a dereference that precedes a later NULL test of the same pointer, a NULL passed to the `%s` conversion of an ISO C or POSIX formatting function (or a project formatter whose body proves it forwards to one), a function-like macro that dereferences a possibly-null pointer argument, and a pointer read after a status check that the callee's own body does not prove sets it; an earlier NULL test whose NULL branch does not leave is no longer a guard.
- EXP34-C no longer reports `&*p`, `&p[i]` or a pointer printed with `%p` as a dereference, the result of a function whose every return is provably non-null (directly, through a local, or through another such function) as possibly NULL, or a pointer passed to a variadic function that is not shown to be a formatter.
- Integer and floating-point rules type a variable by its own declaration, so a same-named variable in an inner block or another function no longer decides whether an operation is checked.
- Floating-point and integer-conversion rules type each operand by its declaration, including struct fields, bit-field promotion and function return types, so integer, pointer and array comparisons are no longer reported as floating-point equality.
- INT32-C reports an overflow when a `long` or `long long` variable holding its type's maximum (`LLONG_MAX`, `LONG_MAX`, `INT64_MAX`) then has 1 added, which v0.5 missed.
- Under a declared data model, an `unsigned long` constant is typed at the model's long width: `(1ul << 56) - 1ul` under lp64 is no longer reported.
- EXP33-C and EXP34-C no longer take minutes on very deeply nested code, such as thousands of nested `if` statements; the time to resolve an identifier no longer grows steeply with nesting depth.

### Removed

- `--export` now writes only SARIF (`.sarif`, `.sarif.json`) and JSON (`.json`); the built-in CSV and XLSX output, including the interactive UI's save dialog, is removed. `scripts/sarif_convert.py` converts a SARIF report to CSV, or to XLSX with `openpyxl`, in the former column layout.
- The per-rule `category`, `cert_id` and `parameters` manifest keys, which had no effect, are removed; a manifest that sets them still loads, with a warning.

## [0.5.3] - 2026-09-24

### Added

- `--compile-commands` now also reads the build's `-D`/`-U` state as a configuration declaration: a macro defined in several mutually exclusive `#if` arms resolves to the definition that build actually compiles, instead of a POSIX platform guess plus first-definition-wins. A `#define` in real source still overrides a build flag, and findings are never suppressed by configuration.
- `--compile-commands` warns when the compile database does not cover every file being scanned, so a partial declaration is visible instead of silently falling back to the default platform profile for the uncovered files.

### Fixed

- MSC13-C no longer reports a variable declared in both arms of an #if in some runs and not others: findings are now identical from run to run.
- ENV30-C no longer treats a mention of getenv() in a comment, or a longer name that merely contains a protected function's name such as curl_getenv(), as the source of a protected pointer, removing false reports about modifying an environment string.
- ENV30-C now reports a struct tm from gmtime()/localtime() passed to mktime() as a definite modification rather than a possible one, so the finding no longer asks for manual review.
- A null check whose early-return branch itself uses the variable (`if (!p) return f(p);`) no longer proves the variable non-null for the rest of the function, so the null dereference inside that branch is reported.
- ENV30-C now recognises an environment string reached through a function pointer bound to getenv(), no longer reads a mention of strchr() in a comment as a real call when tracking pointers derived from protected data, and no longer reports dlopen() as possibly modifying the path string it is given.
- EXP33-C no longer reports a variable passed to a callee as uninitialized when the callee writes it through a call the analysis cannot follow, or hands it on to another function that has not been resolved yet. Such a parameter is treated as unknown, not as read-only.
- EXP34-C reports a possibly-null parameter at the callee's unguarded dereference instead of at each call that passes it. Passing a possibly-null pointer is no longer a finding by itself. A variadic argument, which has no callee-side site, is still reported at the call.
- Value-range analysis no longer oscillates until its iteration cap on some functions. Scans that spent minutes on a single file now finish normally. This affects ARR30-C, INT08-C, INT10-C, INT16-C and INT30-C to INT34-C.
- EXP33-C no longer counts taking a field's address (`&p->field`), or forwarding a cast of the pointer to another call, as a read of the pointer.
- EXP33-C no longer reports an output variable as possibly uninitialized after the caller has checked the return value of a function that writes it on every successful path.
- Calls inside code the C parser recovers only partially (for example, after a macro that expands to a `case` label) now count as callers.
- MEM30-C no longer reports a double free or use-after-free of a struct member that an intervening memset() set back to NULL.
- A pointer passed by address to a function that writes it on only some paths is no longer assumed non-null after the call.
- MEM30-C no longer reports a double free or use-after-free of a struct member after the pointer it hangs off has been pointed at a different object.
- ENV03-C, ENV33-C, INT30-C to INT32-C, STR02-C and FIO30-C no longer treat a comment or string literal that mentions `getenv()` as a source of tainted data.
- A `static` function whose address is taken is no longer treated as though every caller were visible, so a call through a function pointer can no longer be overlooked when proving a parameter non-null.
- MEM30-C no longer reports a double free or use-after-free on a path that a status variable, set alongside the free and tested later, rules out.
- API00-C again reports a function that passes an unvalidated pointer parameter to a helper whose only use of it is taking a member's address (&p->field), a case missed since 0.5.2.
- MEM30-C now recognizes a single-argument deallocator that releases memory through a function pointer, so a use-after-free or double free after calling it is reported instead of silently missed.
- EXP34-C no longer reports a variadic argument as dereferenced when its format conversion only uses the pointer's value (such as `%p`).
- MEM30-C no longer reports a pointer as freed after a loop that frees it on each iteration and exits because the pointer became NULL; a loop left by `break` still keeps the pointer freed.
- MEM31-C no longer reports a finding twice when unexpanded macros make one function appear nested inside another.
- MSC13-C now reports a constant initializer that every path overwrites before reading it. It no longer exempts one because it is a named constant or a literal on the returned variable.
- MEM01-C no longer reports a use after free when the freed pointer is rebound by an output-parameter call whose return value is stored, declared, returned or cast (e.g. `len = format(&buf, ...)`).
- MEM30-C now marks a double free for manual review when either free was inferred from the deallocator's name alone, and keeps that mark on a use-after-free reached through a chain of pointer copies.
- A parameter forwarded through a relay function is no longer proven non-null just because most of the observed callers pass a non-null value.
- DCL18-C now states the correct decimal value for an octal constant with an integer suffix (017L is 15, not 0), and no value for a literal whose digits are not octal.
- MEM31-C's "allocated in loop but not freed" findings now point at the allocation instead of line 1 of the file. Distinct findings in one file are therefore no longer merged into one.
- FIO50-C no longer treats integers shifted with `<<` or `>>` as stream input and output, and reads the stream from the correct argument of `fread()` and `fputs()`.
- A `static` function defined under the same name in several files now resolves to the definition in the calling file, and an externally linked definition takes precedence over a `static` one in another file. A `void *` parameter cast to a local pointer is still the parameter: writes through the local and null checks on it count, and `sizeof(*local)` is not a dereference.
- Cross-function null-state propagation now runs until it converges, instead of stopping after three passes. Findings that depend on a chain of forwarding calls no longer depend on where the analysis happened to stop.

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

[Unreleased]: https://github.com/brandon-arrendondo/aurora-lint/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/brandon-arrendondo/aurora-lint/compare/v0.5.3...v0.6.0
[0.5.3]: https://github.com/brandon-arrendondo/aurora-lint/compare/v0.5.2...v0.5.3
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
