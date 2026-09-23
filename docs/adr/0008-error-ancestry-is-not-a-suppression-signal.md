# 0008. ERROR ancestry is not a suppression signal — fix the preprocessor misread instead

## Status

Accepted

## Context

tree-sitter has no preprocessor. When a construct defeats the C grammar — a
`#if` between two operands, a `##` token paste in a macro body, an unclosed
`asm volatile(`, a trailing export-specifier macro — GLR error recovery
produces an `ERROR` node and reparents whatever it could still parse
underneath it. Rules then walk that tree like any other.

The question "should a rule decline to report when its node has an `ERROR`
ancestor?" has now come up twice. EXP02-C very nearly adopted it
before measurement showed the recall cost: 1 misfire fixed, 10 genuine
findings lost. EXP02-C instead took a narrow name-match fix, declining only a
`call_expression` whose callee is literally `defined`.

Because that decision was made inside one rule, nothing stopped the next rule
from reaching for the same lever. Task 1272 characterized the whole population
so the answer would not have to be rediscovered per-rule.

**Measurement** (all 12 pinned real-world codebases, local characterization
scans; the tool reproduced `CParser`'s full repair pipeline plus the
prescan-derived `RepairMacros`, then resolved the node at each finding's
reported position and walked its ancestors):

- **15,193 of 169,736 findings (8.95%) have an `ERROR` ancestor**, contributed
  by 155 of the 253 firing rules. 752 of 2,085 files carrying findings have a
  parse error.
- The rate is not a property of parse damage. It ranges from 0.00% (libcrc,
  ventoy) and 0.10% (lua — which nonetheless has a parse error in 48 of its 58
  files) to 16.00% (hostap) and 22.07% (pureftpd).
- **The population is 99.1% whole-file *framing* failures.** Median `ERROR`
  span is 5,264 lines; pureftpd's `ftpd.c` is a single 6,312-line `ERROR`
  containing 788 findings. Inside these, the contents parsed normally and were
  merely reparented — the typical ancestor chain is
  `primitive_type → function_definition → ERROR`. Only 143 findings (0.9%) sit
  in a region under 50 lines, which is where genuine token-level confusion
  lives.
- Hand-verified misfire rate differs by roughly 3× between the two:
  **~12% in large regions, ~39% in small ones.**

Three findings make a blanket gate untenable rather than merely expensive:

- **It would gut rules whose true output happens to live in damaged files.**
  ERR34-C (804 of 1,180 findings, 68.1%) and ERR07-C (756 of 1,106, 68.4%)
  draw most of their entire output from `ERROR` regions. Every sampled
  instance is a correct unchecked `atoi()`. The concentration reflects where
  `atoi` is called — hostap's `ctrl_iface.c` is one 15,101-line `ERROR` region
  — not any defect in the finding. EXP19-C contributes 4,945 such findings;
  sampled ones were all genuinely unbraced `if` bodies.
- **For some rules the gate is self-defeating.** PRE32-C flags a preprocessor
  directive inside a function call's argument list; PRE31-C flags an unsafe
  macro invocation whose argument is not a well-formed expression. *The
  construct they detect is the thing that breaks the parse.* sel4's
  `capdl.c:335`/`:353` (a `#if defined(...)` inside `printf`'s arguments) and
  `fastpath.c:669` (`SMP_COND_STATEMENT( || sc->scCore != getCurrentCPUIndex())`)
  are correct findings that an ancestor gate would delete by construction,
  making those rules unable to fire on their own subject matter.
- **`ERROR` ancestry does not predict correctness in either direction.** The
  same rule lands on both sides: MSC12-C misfires at valkey `syscheck.c:407`
  ("stray semicolon" on `{.name = NULL, .check_fn = NULL}};`, which closes an
  initializer) and is correct at sel4 `fastpath.c:215`, where the line
  genuinely ends `;;`. PRE32-C is correct at sel4 `capdl.c:335` and misfires at
  sqlite `vdbeapi.c:1315`, where `SQLITE_DEBUG` is an `#ifdef` guard rather
  than a called function.

The misfires that *do* occur are not randomly distributed. The dominant class
is **preprocessor text reaching a rule that assumes it is looking at a C
expression** — the same family as the EXP02-C `defined()` misfire that started
this:

- INT33-C reads the header path in `#if __has_include(<sys/socket.h>)` as
  division: "Division or modulo by 'socket'" (mbedtls `x509_crt.c:2708`,
  `:2711`).
- PRE31-C reads `#if defined(MBEDTLS_KEY_EXCHANGE_*_ENABLED)` as a
  function-like macro invocation with arguments (mbedtls `ssl_ciphersuites.c`,
  10 sites).
- EXP13-C reads the `<`/`>` of `__has_include(<dlfcn.h>)` as a chained
  relational operator (valkey `module.c:13497`).
- PRE32-C treats `SQLITE_DEBUG`, the macro in `#ifdef SQLITE_DEBUG`, as a
  called function (sqlite `vdbeapi.c:1315`).
- INT33-C and INT10-C report division and modulo on a `wpa_printf()` line
  whose only relevant content is the *string* `"Invalid bss_load_test"`
  (hostap `config_file.c:4252`).

Two smaller classes account for most of the rest: a `#if`/`#endif` splitting a
statement so dataflow loses a write, producing "used uninitialized" *at the
point of assignment* (valkey `module.c:13507` `handle = dlopen(...)`; pureftpd
`ftpd.c:5591` `while ((fodder =`; lua `ltable.c:228` passing `&key` to an
out-parameter); and ADR-0006's name-versus-declaration failure amplified by the
region (curl `multi.c:1743` calls `k->size` unsigned when `lib/request.h:57`
declares it `curl_off_t`, signed, with upstream's own `-1 if unknown` comment;
sqlite `os_win.c` reports "Parameter 'SIZE_T'" six times where `SIZE_T` is a
Windows *type* in a function-pointer cast, and is the platform's size type).

## Decision

**Do not gate a rule on whether its node has an `ERROR` ancestor.** Not as a
noise fix, not as a quick way to kill a misfire, not "just for this rule."

When a rule misfires inside a damaged region, diagnose what it actually
misread. In practice that has been one of three things, in descending
frequency:

1. **Preprocessor text read as a C expression.** Fix the rule to recognize the
   preprocessor construct — the way EXP02-C declines a `call_expression` whose
   callee is literally `defined`. A rule that can be reached from a
   `preproc_if`/`preproc_ifdef` condition, a header-name token, or an
   `#ifdef` guard name needs to say so explicitly.
2. **Dataflow interrupted by a conditional-compilation split**, yielding a
   claim about initialization or reachability that the source contradicts.
3. **An identifier resolved by spelling rather than by declaration** —
   ADR-0006, which the damaged region makes easier to get wrong.

Existing parse-damage guards are **subtree-scoped and stay that way**:
MSC12-C's `find_first_descendant(|n| n.is_error() || n.is_missing())`,
MSC13-C's `node.has_error()`, EXP10-C's `root.has_error()` on a re-parsed macro
snippet. "This node's own subtree failed to parse, so I cannot read it" is a
sound reason for silence. "Something elsewhere in this file failed to parse" is
not.

If a gate ever does seem warranted, **region size is the discriminator, not
ancestry** — a tight `ERROR` region is roughly 3× more likely to yield a
misfire than a whole-file framing failure. At 143 findings corpus-wide it is
not currently worth a mechanism, and fixing the preprocessor class addresses
most of it directly.

## Consequences

- A proposal to suppress on `ERROR` ancestry should be answered with this ADR
  and the 8.95%/99.1% numbers, not re-measured. The measurement is
  reproducible if the question is genuinely new: reproduce `CParser`'s repair
  pipeline with the prescan's `RepairMacros`, resolve the node at each
  finding's reported position, and walk ancestors.
- A rule that fires *only* inside `ERROR` regions is not thereby suspect.
  ERR34-C and ERR07-C are the standing counter-example: ~68% ERROR-ancestor
  origin and correct. Do not read a high ERROR-ancestor share as a defect
  signal — it usually says something about where the flagged construct lives.
- The preprocessor-misread class is a **bug class, not a tuning question**.
  Each instance is a misfire in ADR-0005's sense — the finding names a
  construct a reader of the flagged line cannot find — so ADR-0001's
  "suppression is configuration" and ADR-0002's "low TP rate isn't failure"
  do not apply and must not be used to defer it.
- This ADR does not say findings from damaged regions are trustworthy in
  general. ~12% of the large-region population and ~39% of the small-region
  population are wrong. It says the *ancestry relation* is not what
  distinguishes them, so it cannot be the filter.
- Corollary for anyone reading a scan of a heavily-preprocessed codebase: a
  single `ERROR` can span an entire file, so "this file has a parse error" is
  nearly uninformative — 752 of 2,085 files with findings have one. Parse
  health and finding quality are only loosely coupled: lua has a parse error in
  48 of 58 files and 4 ERROR-ancestor findings; ventoy has 4 damaged files and
  none.
- Credit: measured by dev-180 under task 1272, from the population EXP02-C's
  task 1264 first exposed.
