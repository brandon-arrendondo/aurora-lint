# 0011. What counts as proof: language guarantees and code as written, not compilers or inference

## Status

Accepted (Brandon, 2026-09-24). Makes explicit the exception list ADR-0001
leaves implicit. It governs both what a rule may treat as settled and what an
oracle label may cite as its basis.

## Context

ADR-0001 says a rule reports a violation as written, and that the only thing
that removes a finding from the rule is a detection bug. Every suppression or
FP label therefore has to rest on something that *proves* the flagged
construct is safe. What counts as proof has been settled case by case,
usually in the middle of adjudication:

- `main`'s `argv` is never null, because C11 5.1.2.2.1 requires `argv[argc]`
  to be a null pointer.
- An object with static storage duration and no initializer is
  zero-initialized (C11 6.7.9p10), so reading it is not a use of an
  indeterminate value.
- valkey's `serverAssert` has no `NDEBUG` arm and aborts in every
  configuration, so it guards what follows it. A standard `assert()` does not,
  because `NDEBUG` strips it (ADR-0010, Decision 5).
- An `#if 0` region is not evaluated at all (ADR-0010).
- "No caller in the tree passes NULL" is not proof for a function with
  external callers, such as an exported module API.

These rulings are consistent with each other, but the principle behind them
was never written down. Without it, each new case gets argued from scratch,
and two adjudicators can reach opposite verdicts on the same construct. That
has happened: API00-C labels on `main`'s parameters were split roughly
evenly between TP and FP before the `argv` ruling.

## Decision

A basis for treating a construct as safe, in a rule or in a label, is
accepted or rejected by what it rests on. In order of strength:

1. **Language guarantees: accepted.** What ISO C itself requires of every
   conforming implementation. Examples: `argv[argc] == NULL`; static storage
   is zero-initialized; `free(NULL)` does nothing; `sizeof(char) == 1`. These
   hold on every compiler and in every build, and any reader can check them
   against the standard.
2. **Code that is dead as written: out of scope.** A region the file itself
   proves can never be compiled (`#if 0`, a `defined(MACRO)` arm settled by an
   unconditional `#define`/`#undef` in the same file, `__cplusplus` when
   building C) is not evaluated. Someone could edit it into live code, but
   the scan describes the code as it stands. ADR-0010 defines exactly which
   regions qualify; everything else is live, including arms a particular
   build does not select.
3. **Proof in the scanned source: accepted.** A dominating check on the
   value; an assert or abort macro with no build-flag arm; a callee that
   provably tolerates NULL; a closed set of call sites, all passing a safe
   argument, for a function that cannot be called from outside the corpus
   (internal linkage, or no external entry point). The proof must be visible
   in the code that was scanned.
4. **Compiler and implementation guarantees: not a basis by default.**
   Behavior that depends on a compiler, its flags, or a platform: `-fwrapv`
   making signed overflow defined, `-fno-strict-aliasing`, `int` being 32
   bits on the benchmark host, a C library's behavior beyond what ISO C
   requires, or an attribute such as `nonnull`, which makes a violation
   undefined rather than impossible. None of these travel with the source.
   A label resting on one would change with the machine that built the
   code. The exception is a property the code itself pins down, such as
   `static_assert(sizeof(int) == 4)`, which is then case 3.
5. **Inference: not a basis.** "Every caller I can see passes non-null" for a
   function with external callers. "The tests exercise this." "This idiom is
   obviously intentional." An `NDEBUG`-strippable assert, which relies on a
   debug test suite reaching it. A runtime switch that is off by default,
   such as valkey's `debugServerAssert`. Each of these describes today's
   usage or intent, not the code.

A construct that no accepted basis covers is reported, and a label on it is
TP. That holds even when it is almost certainly harmless in practice.

## Consequences

- A rule fix may teach a rule to recognize bases 1-3. A fix that encodes
  4 or 5 is a suppression heuristic, and ADR-0001 says that belongs in
  configuration, not in the rule.
- An FP label names its basis concretely: the clause of the standard, the
  guarding line, or the enumerated call sites. "Internal contract",
  "caller always passes valid" and "not attacker-controlled" name no basis.
  That is why the task-644 API00-C rows were restated.
- Precision and recall figures do not depend on the toolchain of the host
  that ran the scan. That is the property basis 4 would break.
- **Unused functions stay in scope.** They are compiled, type-checked and
  linked, one call away from live, unlike an `#if 0` region. A function with
  external linkage may also have callers outside the corpus. A `static`
  function with no caller in its file is unreachable as written, but it is
  still compiled, so it is reported like any other code.
- **Checks made by every caller count.** Take a function that nothing
  outside the corpus can call, whose every call site provably tests the
  value before passing it: `if (x) f(x);` at each one. The value reaching
  the function is checked, so the dereference inside is not a finding. This
  is the input-boundary pattern: one validating layer in front of an
  internal layer that doesn't re-check. It is fragile, because new code
  that calls without checking brings the problem back. But that is a
  question about code growth, and a scan of the new code reports the new
  call. It is not a reason to flag the fixed commit being measured. The bar
  is high: *every* call site, provably, with no function-pointer or
  external route in. Most code won't clear it (Brandon, 2026-09-24).
- **Libraries count as external.** A library that the tree builds or
  installs for outside use has an open caller set for every non-static
  function in its source files: a `.so` or `.a` that is documented,
  installed, or linked by an example program. hostap's `libradius`,
  `libpasn.so`, `libwpa_client.so` and `libeap` are examples. In-tree call
  sites prove nothing there, because the callers that matter are outside the
  corpus. Treating a library's own in-tree callers as its full caller set is
  a common trap for analysis tools. It is part of why libcrc, which is only
  a library, is in the corpus. Static functions stay closed.
- **An executable that exports its symbols to plugins is a library too.**
  A link with `-rdynamic` puts every non-static symbol of the executable
  into its dynamic symbol table, where code it loads with `dlopen` can call
  it. hostap's `CONFIG_DYNAMIC_EAP_METHODS` does exactly this for
  `wpa_supplicant`: the build adds `-ldl -rdynamic`, and EAP method plugins
  outside the tree then load into it and call into the binary. The option
  is commented out in `defconfig`, but it compiles, so under ADR-0010 it
  counts. Every non-static function linked into `wpa_supplicant` in that
  build therefore has an open caller set, as a library's does
  (Brandon, 2026-09-25). A plugin interface turns code written as internal
  into a public entry point, so this is where validating input matters most:
  a malformed call from a plugin is an injection or crash route like any
  other. "Then that is a bad plugin" does not close it. Plugins and
  extensions that ship with a codebase are relied on by others whatever
  their quality, and the host is what they run inside.
- **A proof chain has to end in a real proof.** If a caller dereferences a
  pointer before passing it on (`p->x = 1; f(p);`), that dereference is not
  a check. When `p` is unchecked in the caller, the dereference there is its
  own problem one frame up: it moves the fault, it doesn't prove the value
  safe. Such a caller counts only if the chain above it ends in a test, a
  language guarantee, or an address-of or literal argument. The same holds
  for an array member whose base pointer was dereferenced above the call.
  Flag the problem where it is. As with compiler errors, the first site of
  failure goes to the top of the pile. Later sites that depend on it may
  not show until that one is fixed.
- Where the standard leaves something implementation-defined, as it does
  with integer widths, basis 1 does not cover it and basis 4 applies.
- This ADR does not change ADR-0010's rule that every compilable
  configuration counts. A construct that is safe in one build and unsafe in
  another is unsafe, because the unsafe build exists.
