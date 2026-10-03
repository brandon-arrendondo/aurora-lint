Configuration
=============

Manifest File
-------------

The rules manifest TOML file controls which rules are active and their severity.
The default manifest (``rules_templates/rules-all.toml``) enables |rules_enabled| of the |rules_total| tracked rules.
The other |rules_disabled| are tracked but not implemented — see `Tracked but not implemented`_ below.

::

    # Use default (all rules enabled)
    aurora-lint /path/to/code

    # Use a custom manifest
    aurora-lint --manifest my-rules.toml /path/to/code

Custom Manifest Format
----------------------

.. code-block:: toml

    [metadata]
    name = "My Project Rules"
    version = "1.0.0"
    description = "Custom CERT C rules for my project"
    cert_version = "2016"

    [rules.cert_c.ARR30-C]
    enabled = true
    severity = "High"
    description = "Do not form or use out-of-bounds pointers or array subscripts"

    [rules.cert_c.STR31-C]
    enabled = false  # Disable this rule
    severity = "Medium"
    description = "Guarantee that storage for strings has sufficient space"

Policy and Environment Settings
-------------------------------

Two settings, separate from which rules run, decide what the enabled rules
assume (ADR-0015):

- **Policy** says what the rules require of the code, and so which findings
  are reported. ``default`` credits the assumptions mainstream analyzers make
  (for example, a dominating ``assert`` is a guard even though ``NDEBUG`` can
  strip it). ``strict`` credits none of them: the reading MISRA-style and
  certified code needs.
- **Environment** says what the analyzer may believe about the platform the
  code runs on. ``hosted`` trusts the ISO C and POSIX library contracts (for
  example, ``free(NULL)`` does nothing) and ``main``'s ``argv`` guarantees.
  ``freestanding`` trusts no library semantics beyond the language unless a
  ``libc`` model is declared. The environment is always declared, never
  guessed from the machine running the scan.

Two presets set both at once. The **default** preset is the default policy on
a hosted environment. The **strict** preset is the strict policy on a
freestanding environment, for teams that trust nothing. Any combination can
be set explicitly, down to single options:

.. code-block:: toml

    profile = "strict"          # preset: "default" (the default) or "strict"

    [metadata]
    name = "Firmware rules"
    version = "1.0.0"
    cert_version = "2016"

    [policy]
    level = "strict"            # "default" | "strict"; overrides the preset

    [environment]
    kind = "freestanding"       # "hosted" | "freestanding"; overrides the preset
    libc = "newlib"             # iso-posix | glibc | musl | newlib | picolibc | custom
    include_names = "exact"     # "exact" | "case-insensitive" (as cl on Windows)
    data_model = "lp64"         # preset: "iso" (the default) | "ilp32" | "lp64" | "llp64"
    # int_bits = 32             # integer facts the preset loads; write one to
    #                           # override it (see below)

    [environment.overrides]
    static_zero_init = false    # our startup code does not clear .bss

    [environment.deallocators]
    MBEDTLS_PLATFORM_FREE_MACRO = 1     # frees its first argument
    [environment.allocators]
    MBEDTLS_PLATFORM_CALLOC_MACRO = "calloc"

    [rules.cert_c.EXP34-C]
    enabled = true

The same settings are available on the command line, where they win over the
manifest: ``--profile``, ``--policy``, ``--environment``, ``--libc``,
``--include-names``, ``--data-model``, the repeatable ``--allocator NAME[=CONTRACT]`` and
``--deallocator NAME[=ARG]``, and a repeatable ``--set NAME=VALUE``. A
``--profile`` given on the command line starts again from that preset,
discarding the manifest's settings except its declared allocators and
deallocators, its ``data_model`` and its integer facts: those say what the project's own
functions do and what it is built for, which a preset never changes.

``aurora-lint --list-options`` lists every option with its value under each
preset and under the current settings (``--list-options json`` for tooling).
:doc:`options` is generated from the same table. An unknown option name, or
one set on the wrong axis, is an error naming the allowed set. A SARIF
export records the settings in ``runs[0].properties["aurora-lint/settings"]``,
so a report always says which reading produced it. Its ``hash`` is the SHA-256
of the settings' canonical JSON (sorted keys): equal settings always hash
equally, and changing any option's value changes it.

``include_names`` says how an ``#include`` name is matched against the files on
disk. It describes the toolchain rather than an assumption the rules trust, so
neither preset sets it. Left unset, it is ``case-insensitive`` when
``--compile-commands`` names a cl or clang-cl build (see :doc:`cli-usage`) and
``exact`` otherwise. The file system of the machine running the scan never
decides it. It enters the settings hash only when ``case-insensitive``, so
settings that never mention it keep the hash they always had.

Integer widths are implementation-defined, so the scan credits only what it is
told. Each width is a plain key under ``[environment]``, and ``data_model`` is a
named **preset**: a bundle of those keys, loaded as if its lines were in the
configuration. Selecting ``data_model = "lp64"`` and writing the keys it loads
by hand are the same thing.

.. list-table::
   :header-rows: 1

   * - key
     - what it is
     - ``ilp32``
     - ``lp64``
     - ``llp64``
     - ISO minimum
   * - ``char_bits``
     - bits in a ``char`` (``CHAR_BIT``)
     - 8
     - 8
     - 8
     - 8
   * - ``short_bits``
     - bits in a ``short``
     - 16
     - 16
     - 16
     - 16
   * - ``int_bits``
     - bits in an ``int``
     - 32
     - 32
     - 32
     - 16
   * - ``long_bits``
     - bits in a ``long``
     - 32
     - 64
     - 32
     - 32
   * - ``long_long_bits``
     - bits in a ``long long``
     - 64
     - 64
     - 64
     - 64
   * - ``pointer_bits``
     - bits in a pointer, ``size_t``, ``ptrdiff_t``, ``intptr_t``
     - 32
     - 64
     - 64
     - 16
   * - ``wchar_t_bits``
     - bits in a ``wchar_t``
     - unknown
     - unknown
     - 16
     - 8
   * - ``char_signed``
     - whether plain ``char`` is signed
     - unknown
     - unknown
     - unknown
     - none
   * - ``float_bytes``
     - ``sizeof(float)``
     - 4
     - 4
     - 4
     - none
   * - ``double_bytes``
     - ``sizeof(double)``
     - 8
     - 8
     - 8
     - none
   * - ``long_double_bytes``
     - ``sizeof(long double)``
     - 12
     - 16
     - 8
     - none
   * - ``time_t_bytes``
     - ``sizeof(time_t)``
     - unknown
     - 8
     - unknown
     - none
   * - ``off_t_bytes``
     - ``sizeof(off_t)``
     - unknown
     - 8
     - unknown
     - none

``iso``, the default preset, loads nothing. A preset is nothing but a list of
these keys: writing ``lp64``'s lines under ``[environment]`` gives the same
facts and findings as selecting it; the settings hash and the data model shown
by ``--list-options`` differ. Facts
describe the target the code is built for, and none is required; each has a
stated default, the ISO C guarantee or unknown.

Where a fact comes from, highest precedence first:

1. the command line (``--set key=value``, ``--data-model``);
2. the project's own ``[environment]`` keys;
3. the selected preset's bundle;
4. the floor, which is what ISO C guarantees: ``CHAR_BIT`` at least 8,
   ``short`` and ``int`` at least 16 bits, ``long`` at least 32, ``long long``
   at least 64, the rank order, and the exact width of ``int32_t`` and its
   kind.

An explicit key beats the preset whatever order the lines are in. A key that
only repeats the value of the bundle its own configuration names declares
nothing: it is not part of the settings hash, and a ``--set`` that repeats the
preset hashes the same as one in a file. When the command line names another
data model, that model's bundle replaces the file's whole bundle, the lines the
file only repeated from its own model included, while a line that differs from
the file's model still wins. ``--list-options`` shows who wrote a line
(``cli`` or ``config``) even when its value equals the preset's. A fact
nothing sets is **unknown**, and a scan then credits only the floor: a value is
proven to fit a type only inside its guaranteed range, a defect that occurs at
some conforming width (``unsigned char * unsigned char`` overflowing a 16-bit
``int``) is reported, and nothing is proven or reported through a guessed
value. No data model sets ``wchar_t_bits`` but ``llp64`` (a Windows-only
model): ``ilp32`` and ``lp64`` are Linux and Windows targets alike, so a
project declares its own. No preset sets ``char_signed``; until it is declared,
``CHAR_MAX`` and ``CHAR_MIN`` are not numbers, and a proof that goes through
one is lost.

.. code-block:: toml

    [environment]
    data_model = "ilp32"        # the preset: loads 32-bit int, long and pointers
    wchar_t_bits = 16           # override: for a Windows build, whose wchar_t is 16 bits
    char_signed = true          # plain char is signed on this target

``aurora-lint --list-options`` prints every integer fact with its value and
where it came from (``cli``, ``config``, ``preset:NAME``, ``iso-floor`` or
``unknown``), one line per fact, so you can see exactly what a scan will
credit; ``--list-options json`` carries the same rows under ``facts``.
``aurora-lint --check-config`` resolves the settings from the manifest and the
command line exactly as a scan would, validates them, and exits without
scanning: ``configuration ok`` and status 0 when valid, otherwise status 1 and
one ``error:`` line per problem. Both use the code a scan runs, so they cannot
disagree with it.

Precedence, highest first: the command line (``--set``, ``--data-model``), the
project's own keys, the data-model preset's bundle, the ISO minimum. An explicit
key beats the preset whatever the order of the lines; a key that only repeats
what the preset loads declares nothing.

``aurora-lint --write-config FILE`` writes a complete configuration with every
settings key and a one-line description of each. A key at its built-in default
is commented out; with ``--data-model X`` or ``--set`` the preset's bundle
values are active lines marked ``# from preset: X``, and a fact no preset sets
is written commented out as ``# unknown unless declared``. It is generated from
the same tables as ``--list-options`` and the validation, so it cannot drift
from them, and the file it writes passes ``--check-config`` unchanged and
resolves to exactly the facts of running without it (or with the same
``--data-model``). It refuses to replace an existing ``FILE`` unless
``--overwrite`` is given; ``--write-config -`` prints to stdout. The workflow:

.. code-block:: console

    $ aurora-lint --write-config aurora.toml --data-model lp64
    $ $EDITOR aurora.toml                    # e.g. uncomment char_signed
    $ aurora-lint --check-config -m aurora.toml
    configuration ok
    $ aurora-lint -m aurora.toml src/

A width below its ISO minimum, a width that is not a whole number of 8-bit
bytes or exceeds 64 bits, and a rank order that shrinks
(``short <= int <= long <= long long``, among the widths that are known) are
refused with the offending key named: the configuration describes no
conforming implementation. Every declared override is a key of the settings
hash and is shown in ``--list-options`` and in a SARIF export, while the run
label still names only the preset. Each problem is reported once, however
many rules it breaks. The size keys (``float_bytes``, ``double_bytes``,
``long_double_bytes``, ``time_t_bytes``, ``off_t_bytes``) are checked to be
1 to 64 bytes, with no ISO minimum enforced. A command-line argument the parser
itself rejects, such as an unknown ``--data-model`` name, is an
argument-syntax error and exits 2; every problem in a value that parses exits 1
under ``--check-config``.

Under ``iso``, an integer constant too wide for a 16-bit ``int`` is taken to be
at least 32 bits wide (``int`` on most targets, ``long`` otherwise); an
implementation with an ``int`` between 17 and 31 bits is not modelled. Declare
``int_bits`` for such a target.

Under ``iso`` ``INT_MAX`` and ``LONG_MAX`` are unknown, and so is
``sizeof(long)`` to the integer rules and the range analysis. The buffer-size
checks of ARR30-C, ARR38-C and STR31-C do not follow the facts yet: they still
size an ``int`` as 4 bytes, a ``long`` and a pointer as 8, whatever is
declared.

Under ``iso`` even a 64-bit exact-width type such as ``uint64_t`` is not known
to be at least as wide as ``int`` (ISO C gives ``int`` no upper bound), so a
bitwise operation on one is still reported by EXP14-C as acting on a type ISO C
does not guarantee is at least as wide as ``int``; declaring a data model
clears it. Constant expressions such as ``24 * 3600`` or ``1 << 27`` overflow a
16-bit ``int``, so an undeclared project is told about them too; declaring a
model, or ``int_bits``, clears them.

A known limitation of an unknown width: a limit macro is not a number, so a
proof that goes through its value is lost even when it holds on every
implementation. ``x = INT_MAX; x + 1`` overflows everywhere, and a branch
guarded by ``d < SHRT_MAX`` after ``d = SHRT_MAX`` never runs, but with
``INT_MAX`` and ``SHRT_MAX`` unknown neither is proven: an undeclared project
loses such an overflow finding and can be reported inside such a dead branch.
Declaring the data model avoids both. The same goes for ``sizeof`` of a type
whose width is unknown: a product that includes one is not evaluated, so a wrap
that needs the exact size to show is not reported. An unknown ``wchar_t`` is
still an integer type, no wider than the widest integer the facts declare, and
is bounded by it: ``calloc(n, sizeof(wchar_t))`` cannot wrap a 64-bit
``size_t`` whatever ``wchar_t`` is, and can wrap a 32-bit one.

``allocators`` and ``deallocators`` declare functions the scan has no body
for, such as a platform hook the build supplies: a deallocator frees the
argument its position names, and an allocator follows the contract of the
standard allocator it names. :doc:`options` has the details. They enter the
settings hash only when something is declared.

A function counts as freeing its argument only where the scan can show it: its
body frees it, directly or through wrappers the scan also reads, a macro it
expands to does, or it is declared here. A name such as ``*_free``,
``destroy_*`` or ``*_cleanup`` proves nothing on its own, so an allocation
handed to a library's deallocator with no body in the scan is reported leaked
until that deallocator is declared. ``--report-deallocator-candidates`` (see
:doc:`cli-usage`) lists the callees worth declaring.

Scope
-----

A ``[scope]`` table lists path globs, relative to the scanned root, that the
scan leaves out. It adds to the command line's ``--exclude-all``,
``--report-exclude`` and ``--prescan-exclude`` (see :doc:`cli-usage`):

.. code-block:: toml

    [scope]
    exclude_all = ["tests/**", "docs/examples/**"]  # out of everything
    report_exclude = ["vendor/**"]                  # no findings, still read
    prescan_exclude = ["port/win32/**"]             # reported, not read

``exclude_all`` and ``prescan_exclude`` change what the cross-file facts can hold,
so they enter the settings hash (only when non-empty) and a SARIF export's
recorded settings.

Excluding code, disabling a rule and suppressing findings are the project's
own declarations; :ref:`project-controls` sets the four controls side by side
and says when each one fits.

Supported CERT C Rules
----------------------

|rules_total| rules are tracked across 17 categories; |rules_enabled| are implemented and enabled by
default (the remaining |rules_disabled| are tracked but not implemented — see
`Tracked but not implemented`_ below):

==========  ======  ===========================================================
Category    Count   Rules
==========  ======  ===========================================================
**API**     9       API00-C through API10-C (selected)
**ARR**     9       ARR00-C through ARR39-C (selected)
**CON**     23      CON01-C through CON50-C (selected)
**DCL**     31      DCL00-C through DCL41-C (selected)
**ENV**     8       ENV01-C through ENV34-C (selected)
**ERR**     11      ERR00-C through ERR34-C (selected)
**EXP**     31      EXP00-C through EXP47-C (selected)
**FIO**     35      FIO01-C through FIO51-C (selected)
**FLP**     13      FLP00-C through FLP37-C (selected)
**INT**     23      INT00-C through INT36-C (selected)
**MEM**     17      MEM00-C through MEM36-C (selected)
**MSC**     10      MSC04-C through MSC41-C (selected)
**POS**     20      POS01-C through POS54-C (selected)
**PRE**     16      PRE00-C through PRE32-C (selected)
**SIG**     7       SIG00-C through SIG35-C (selected)
**STR**     16      STR00-C through STR38-C (selected)
**WIN**     6       WIN00-C through WIN30-C (selected)
==========  ======  ===========================================================

For the full list, see ``rules_templates/rules-all.toml`` or the rule source files
in ``src/rules/cert_c/``.

.. _relaxed-onboarding:

Strict vs. Relaxed Onboarding
-----------------------------

Dropping aurora-lint into CI/CD against an existing codebase for the first
time can surface a large number of findings before you have had a chance to
triage any of them — real-world precision varies a lot by codebase (see
``docs/tool-comparison.rst`` for measured figures). Two
things help without writing a manifest at all:

- ``--min-severity``/``--fail-on-severity`` (see `Getting Started
  <../README.md#getting-started>`_ in the top-level README) filter what is
  printed and what fails a build, independent of the manifest.
- ``--exclude-all`` drops generated files and test harnesses from the scan
  entirely — usually the single biggest volume reduction on a first run. For
  vendored code the product links, ``--report-exclude`` silences its findings
  while its definitions keep informing the checks on your own code (see
  :doc:`cli-usage`).

For a coarser starting point than either of those, build your own
**relaxed** manifest the same way this project's own real-world benchmark
suite builds one per codebase (``conf/realworld/*-rules.toml`` — read
``conf/realworld/README.md`` for the full discipline, summarized here):

1. Start from ``rules_templates/rules-all.toml`` (the full default rule set —
   this is the same file aurora-lint embeds and ships) and copy it as your
   starting point, rather than writing a manifest from scratch.
2. Disable a rule wholesale only for one of two reasons, each recorded as a
   comment on its ``enabled = false`` line: it is **categorically
   inapplicable** to your codebase (a Windows-only rule on a POSIX-only
   project, ``FIO*`` on a library with no file I/O), or you are
   **deliberately deferring it** while your team builds up triage capacity,
   with a plan to turn it back on.
3. **Do not disable a rule just because it looks "advisory" or "style," and
   do not disable one on a first impression of noise without measuring
   it first.** This project shipped exactly that manifest once — thirteen
   rules turned off across seven codebases on an "advisory/style" label —
   and measuring the two codebases that kept them found six of the
   thirteen were the *best-precision* rule group in the whole suite. All
   thirteen run everywhere again. A rule that looks noisy on unfamiliar
   code is common; a rule that is actually low-value on *your* code is a
   claim worth checking against your own findings before it goes in a
   manifest, not before.

**There is no single relaxed manifest shipped today**, and that is a
deliberate gap rather than an oversight: real-world noise is measurably
project-dependent (that is the whole reason ``conf/realworld/*.toml`` files
do not inherit from a shared base), so a one-size-fits-all "these rules are
noisy" list would risk the exact mistake above on whichever project doesn't
match its assumptions. A data-driven relaxed starter, generated from
aggregate real-world precision across this project's own benchmark corpus
rather than hand-picked, is tracked as a follow-up rather than shipped
speculatively here.

Tracked but not implemented
----------------------------

|rules_disabled| of the |rules_total| tracked rules have a rule directory and a manifest entry but no
detection logic (no ``.rs`` file). This is a deliberate policy, not a gap:
aurora-lint does not implement against incomplete CERT-C rule content, since there is
ample well-established work to do and a stub implementation would mean
inventing a rule CERT itself has not written.

Two are parked on upstream CERT publishing real content for the rule:

- **ENV04-C** — *Protect programs whose behavior can be controlled by
  environment variables*. CERT's page carries only OpenMP environment-variable
  framing; severity, likelihood, priority and level are all unscored, and
  there is no formal description, no compliant/noncompliant examples, and no
  CWE mapping. `CERT wiki page
  <https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/recommendations/environment-env/env04-c>`__.
  Will be implemented once CERT ships real content; tracked as a gate task
  until then.
- **MSC25-C** — *Do not use insecure or weak cryptographic algorithms*.
  CERT's scraped description is the single sentence "This rule is a stub,"
  with zero CWE references. `CERT wiki page
  <https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/recommendations/miscellaneous-msc/msc25-c>`__.
  Will be implemented once CERT ships real content; tracked as a gate task
  until then.

The other two are ordinary backlog — CERT's content for them is complete, they
are simply not yet written:

- **MSC18-C** — CERT's description and risk assessment are complete (severity
  Medium, 7 CWE references), and one ``pass`` fixture is already staged.
- **MSC19-C** — CERT's description and risk assessment are complete
  (severity Low), and 2 ``fail`` + 2 ``pass`` fixtures are already staged —
  the closest of the 4 to being implementable.

Enabled but out of scope
-------------------------

The four rules above have no detection logic *yet*. This is a different
list: rules that **do** have a ``.rs`` file, **are** enabled by default, and
count toward |rules_enabled| above, but are not claimed as working
detection — because no amount of further work makes them one. A rule
belongs here only when there is a specific, checkable reason automated
analysis cannot do the job, not merely because it has produced few or no
true positives so far (that alone is ``docs/adr/0002`` territory — a low
real-world true-positive rate does not by itself mean a rule is broken or
unneeded — not this list).

- **FLP01-C** — *Take care in rearranging floating-point expressions*. CERT
  itself classifies this rule as unenforceable through automated analysis:
  telling an intentional floating-point reassociation from one that breaks a
  precision requirement needs to know what precision the code actually
  needs, which is not recoverable from the source text. aurora-lint ships a
  documented no-op (``check()`` unconditionally returns no violations)
  rather than a heuristic CERT itself does not endorse. See
  ``src/rules/cert_c/FLP/FLP01-C/flp01_c.rs`` for the rule's own reasoning.

This list is expected to grow. Benchmarking every enabled rule against
Juliet and the real-world corpus (:doc:`testing-methodology`) can surface
a rule where the same case applies for a measured rather than a
CERT-declared reason — repeated, careful measurement finding no codebase
shape this class of static analyzer can reliably resolve, as opposed to a
rule that is simply unproven so far. README's `Rules Out of Scope for
Static Analysis <../README.md#rules-out-of-scope-for-static-analysis>`_
table is the summary of this same list, kept in sync by hand.
