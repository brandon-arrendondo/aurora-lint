Configuration
=============

Manifest File
-------------

The rules manifest TOML file controls which rules are active and their severity.
The default manifest (``rules_templates/rules-all.toml``) enables |rules_enabled| of the |rules_total| tracked rules.
Of the other |rules_disabled|, |rules_withheld| are implemented but withheld because they misfire (see `Withheld until rewritten`_ below)
and |rules_unimplemented| are tracked but not implemented (see `Tracked but not implemented`_ below).

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
    enabled = false
    disabled_reason = "string sizes are checked by our own allocator wrapper"
    severity = "Medium"
    description = "Guarantee that storage for strings has sufficient space"

A disabled rule's block may say why in ``disabled_reason``. Nothing reads a
comment, but ``--check-config`` prints this key for each rule the
configuration disables, a ``--rules`` that names the rule repeats it in its
warning, a SARIF export records it as the rule's ``disabledReason``
(``(no reason given)`` when the block has none), and ``--list-rules json``
gives it as the rule's ``disabled_reason`` (``null`` when the block has
none). It changes nothing about
what runs, and is not part of the settings hash. A rule that is enabled keeps
the key without effect.

A misspelled table or key is refused, except under ``[metadata]``, in a
rule's block, and under an unknown ``[rules.*]`` family (for example
``[rules.certc.ARR30-C]``), where it is ignored. In a rule's block,
``category``, ``cert_id`` and ``parameters`` (removed keys that never had an
effect) load with a warning.

Policy and Environment Settings
-------------------------------

Two settings, separate from which rules run, decide what the enabled rules
assume (ADR-0015):

- **Policy** says what the rules require of the code, and so which findings
  are reported. ``default`` credits the assumptions mainstream analyzers make
  (for example, a dominating ``assert`` is a guard even though ``NDEBUG`` can
  strip it). ``strict`` applies each rule as written: it credits only what
  the rule's text and the C standard credit (a function declared
  ``_Noreturn`` does not return), not a strippable ``assert``: the reading
  MISRA-style and certified code needs. ``pedantic`` goes beyond a rule's
  text where the rule has a closed-form reading stricter than the
  text (only a body shown never to return ends a path), and may decline a
  rule that has none.
- **Environment** says what the analyzer may believe about the platform the
  code runs on. ``hosted`` trusts the ISO C library contracts (for
  example, ``free(NULL)`` does nothing) and ``main``'s ``argv`` guarantees.
  The POSIX contracts hold where POSIX is a declared fact (``posix_version``,
  below), and the default preset assumes it.
  ``freestanding`` trusts no library semantics beyond the language unless a
  ``libc`` model is declared. The environment is always declared, never
  guessed from the machine running the scan.

Three presets set both at once. The **default** preset is the default policy
on a hosted environment that assumes POSIX (with no edition of it), and the
**strict** preset is the strict policy on a hosted environment that assumes
only ISO C: both trust the ISO C library unless a ``libc`` is declared, but
strict applies a POSIX contract or exemption only when ``posix_version`` is
declared, in the configuration or by a compile database passed with
``--compile-commands`` (see *Declaring the platform* below). A strict scan with
neither names the missing fact and the enabled rules whose exemption waits on
it. The **pedantic** preset is the pedantic policy on a hosted
environment that trusts only a declared library: small targets often link a
reduced one, so a full ISO C library is not assumed. With no ``libc``
declared, a pedantic scan trusts no library contract and says so on stderr,
naming the key to declare and the enabled rules a project could disable
instead (``--check-config`` warns the same way).

The presets also differ on the data model (the integer widths, below) when
none is declared. The default preset, the relaxed one, assumes the common
hosted model, LP64 (32-bit ``int``, 64-bit ``long`` and pointers), as a
developer expects. The strict preset credits only the widths ISO C guarantees
(a 16-bit ``int``, a 32-bit ``long``). The pedantic preset needs the data model
declared: without one it credits the ISO C widths and says so on stderr, as it
does for the library. A declared data model, or one a compile database states,
always wins, and a freestanding target is never assumed to be LP64. The scan's
summary, its SARIF settings and ``--check-config`` name the data model in force
and where it came from.

A preset may decline a rule rather than run a reading it cannot state in
closed form (``not_enforced`` in :doc:`rule-presets`). A scan under that preset
does not run the rule, whatever the manifest enables: its summary lists each declined
rule with the reason, its SARIF settings carry them, and ``--check-config``
names them. The summary and ``--check-config`` list only the declined rules the
manifest enables. The SARIF settings (``declined`` and the hashed
``declined_rules``) list every rule the policy declines, enabled or not, so
the settings hash depends on the policy and not on the manifest. A rule every preset declines is a decided cut, not a preset's
choice, and still runs until it is removed. Benchmark precision and recall are
scored against the strict reading. ``--policy`` changes only the
policy axis: ``--policy pedantic`` alone keeps the default preset's hosted
environment and its library. Any combination can be set explicitly, down to
single options:

.. code-block:: toml

    profile = "strict"          # preset: "default" (the default), "strict" or "pedantic"

    [metadata]
    name = "Firmware rules"
    version = "1.0.0"
    cert_version = "2016"

    [policy]
    level = "strict"            # "default" | "strict" | "pedantic"; overrides the preset

    [environment]
    kind = "freestanding"       # "hosted" | "freestanding"; overrides the preset
    libc = "newlib"             # iso-posix | glibc | musl | newlib | newlib-nano | picolibc | custom
    libc_version = "4.4.0"      # recorded and hashed; grants no contract
    c_standard = "c99"          # c89 | c99 | c11 | c17 | c23; unknown unless declared
    posix_version = "none"      # none | pre2001 | 2001 | 2008 | 2017 | 2024; unknown unless declared
    include_names = "exact"     # "exact" | "case-insensitive" (as cl on Windows)
    data_model = "lp64"         # "iso" | "ilp32" | "lp64" | "llp64"; unset: lp64 under the default preset, iso otherwise
    # int_bits = 32             # integer facts the data model loads; write one to
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

**Declaring the platform.** ``c_standard``, ``posix_version`` and the target
(``data_model``) are facts the project declares, never ones the scan finds on
the machine running it. A fact comes from the configuration (a file, or
``--set posix_version=2008``) or from a compile database passed with
``--compile-commands``, which is a declaration of its own: ``-std=`` names the C
edition, ``-D_POSIX_C_SOURCE=`` or ``-D_XOPEN_SOURCE=`` the POSIX edition (a
value older than POSIX.1-2001, such as ``-D_POSIX_C_SOURCE=199506L`` or
``-D_XOPEN_SOURCE=500``, or the bare ``-D_POSIX_C_SOURCE``, declares ``pre2001``;
``-D_POSIX_C_SOURCE=`` with an empty value defines the macro as empty, which glibc
does not read as POSIX, so it declares nothing and is reported), and ``-m32`` or ``-m64`` the
data model (``-m64`` is LP64, or LLP64 for a MinGW target). A flag that looks
like an edition declaration but names none the tool knows (``-std=c2y``,
``-D_POSIX_C_SOURCE=FOO``) is reported and treated as undeclared; it is never
rounded to a nearby edition.

The configuration holds for the whole project and wins a disagreement, which
the scan reports on stderr (``--check-config`` too; a large database gets the
first few conflicts and a count). A compile database's facts are *recorded* per
translation unit, so a settings report shows which units declared what, but
the rules today read one project-wide answer:

- ``posix_version`` from the configuration holds for every scanned file.
- From a compile database alone, a contract that is not read per unit (the
  POSIX entries of ``stdlib_noreturn`` and ``stdlib_call_effects``) holds only
  when *every* unit of the database declares POSIX, and then it holds for every
  scanned file, including a ``.c`` file the database does not compile. A
  database in which some unit declares nothing grants none.
- The data model comes from a compile database only when every unit states the
  same one. A unit that states none leaves it unknown; it is never inferred
  from the units that do.
- ``c_standard`` is read per unit: the configuration's, else the compile
  database's entry for the file. MSC17-C and MSC37-C read it (whether
  ``unreachable`` is a macro the standard defines), and so does the expression
  typing the floating-point and integer rules share: a call to a floating
  function C99 added (``round``, ``cbrt``, ``wcstod``, ...) whose header was
  not expanded has the standard's return type only under a declared C99 or
  later, since C90 left those names to programs. An undeclared edition
  withholds that type rather than taking an exemption, which is why
  ``--pedantic`` names only the missing ``posix_version``.

The settings record where each declared fact came from (``cli``, ``config`` or
``compile database``), and that source is part of the settings hash; a scan
with no declaration and no compile database hashes as it always did.

When a fact is unknown, no exemption that depends on it applies. The default
preset is the one exception: it assumes POSIX, with no edition, because most
code runs on a POSIX system. ``strict`` and ``pedantic`` do not, so a
``--strict`` scan of POSIX code that declares nothing reports the findings the
POSIX exemptions would have withheld. Declare ``posix_version``, or pass a
compile database that defines ``_POSIX_C_SOURCE`` for every unit, to restore
them.

Some facts no other declaration implies. Whether a handler installed with
``signal()`` stays installed while it runs is implementation-defined in C11
(7.14.1.1p3) and in POSIX.1-2024's ``signal()`` alike, so neither a declared
``posix_version`` nor the machine running the scan establishes it. SIG34-C's
exception for a handler that changes its own signal (CERT's SIG34-C-EX1, "for
implementations with persistent signal handlers") applies under every preset
only when the project declares it:

.. code-block:: toml

    [environment.overrides]
    signal_handlers_persistent = true   # our platform keeps handlers installed

or ``--set signal_handlers_persistent=true``. A preprocessor guard such as
CERT's ``#if !defined(_WIN32)`` names a platform, not a persistent one, and is
not read as the declaration.

Integer widths are implementation-defined, so the scan credits only what it is
told. Each width is a plain key under ``[environment]``, and ``data_model`` is a
named bundle of those keys, loaded as if its lines were in the
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

``iso`` loads nothing: it is the data model of the strict and pedantic presets
when none is declared, and the default preset's assumes ``lp64`` instead. A data
model is nothing but a list of
these keys: writing ``lp64``'s lines under ``[environment]`` gives the same
facts and findings as selecting it; the settings hash and the data model shown
by ``--list-options`` differ. Facts
describe the target the code is built for, and none is required; each has a
stated default, the ISO C guarantee or unknown.

Where a fact comes from, highest precedence first:

1. the command line (``--set key=value``, ``--data-model``);
2. the project's own ``[environment]`` keys;
3. the selected data model's bundle;
4. the floor, which is what ISO C guarantees: ``CHAR_BIT`` at least 8,
   ``short`` and ``int`` at least 16 bits, ``long`` at least 32, ``long long``
   at least 64, the rank order, and the exact width of ``int32_t`` and its
   kind.

An explicit key beats the data model whatever order the lines are in. A key that
only repeats the value of the bundle its own configuration names declares
nothing: it is not part of the settings hash, and a ``--set`` that repeats the
data model hashes the same as one in a file. When the command line names another
data model, that model's bundle replaces the file's whole bundle, the lines the
file only repeated from its own model included, while a line that differs from
the file's model still wins. ``--list-options`` shows who wrote a line
(``cli`` or ``config``) even when its value equals the data model's. A fact
nothing sets is **unknown**, and a scan then credits only the floor: a value is
proven to fit a type only inside its guaranteed range, a defect that occurs at
some conforming width (``unsigned char * unsigned char`` overflowing a 16-bit
``int``) is reported, and nothing is proven or reported through a guessed
value. No data model sets ``wchar_t_bits`` but ``llp64`` (a Windows-only
model): ``ilp32`` and ``lp64`` are Linux and Windows targets alike, so a
project declares its own. No data model sets ``char_signed``; until it is declared,
``CHAR_MAX`` and ``CHAR_MIN`` are not numbers, and a proof that goes through
one is lost.

.. code-block:: toml

    [environment]
    data_model = "ilp32"        # the data model: loads 32-bit int, long and pointers
    wchar_t_bits = 16           # override: for a Windows build, whose wchar_t is 16 bits
    char_signed = true          # plain char is signed on this target

``aurora-lint --list-options`` prints every integer fact with its value and
where it came from (``cli``, ``config``, ``data-model:NAME``, ``iso-floor`` or
``unknown``), one line per fact, so you can see exactly what a scan will
credit; ``--list-options json`` carries the same rows under ``facts``.
``aurora-lint --check-config`` resolves the settings from the manifest and the
command line exactly as a scan would, validates them, and exits without
scanning: ``configuration ok`` and status 0 when valid, followed by the data
model in force and where it came from, each rule the policy declines with
the reason, and each rule the configuration disables with its
``disabled_reason``, otherwise status 1 and one ``error:`` line per problem. Both use the code a scan runs, so they cannot
disagree with it.

``aurora-lint --write-config FILE`` writes a complete configuration with every
settings key and a one-line description of each. A key at its built-in default
is commented out; with ``--data-model X`` or ``--set`` the data model's bundle
values are active lines marked ``# from data model: X``, and a fact no data model sets
is written commented out as ``# unknown unless declared``. The data model the
preset uses when none is declared is shown but commented out, with the reason:
``# data_model = "lp64"  # assumed by the default preset; declare it to make it
yours`` under the default preset, ``iso`` with the ISO C minimums under strict
and pedantic. Writing the file therefore declares nothing (an assumed and a
declared ``lp64`` hash differently), and neither is a model a compile database
states written as a declaration; a declared one is, ``iso`` too under the
default preset, where leaving it out would assume ``lp64``. It is generated from
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
    data model: lp64 (config)
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

Thread-API families
~~~~~~~~~~~~~~~~~~~

The concurrency rules read the hazard CERT names, not one API's spelling
(``docs/design/thread-api-families.md``). CON30-C and CON36-C ask which thread
operation a call performs: thread create, mutex lock, condition wait, storing
thread-specific data and so on. Each operation's operands are placed by
argument position. C11 ``<threads.h>`` is always read. POSIX threads are read
too, unless ``posix_version = "none"`` or ``posix = "off"`` below says the
target is not POSIX. A call counts when its callee resolves to the function;
a parameter or a function pointer spelled like one is not it.

An RTOS's API is read only when the project declares it. ``families`` selects
a profile shipped with aurora-lint. ``freertos`` is checked against
FreeRTOS-Kernel V11.2.0 and covers task creation, the recursive-mutex calls,
the thread-local storage pointers and the task delays. It also reads the
kernel heap: ``pvPortMalloc`` allocates as ``malloc`` does and ``vPortFree``
frees. That holds for every memory rule, not only the thread-local storage
check: selecting ``freertos`` makes the two an allocator and a deallocator
everywhere, as declaring them under ``[environment.allocators]`` and
``[environment.deallocators]`` would. The project's own
wrappers go under ``functions``, each with its operation and the 1-based
positions of its operands:

.. code-block:: toml

   [environment.threads]
   families = ["freertos"]

   [environment.threads.functions]
   os_mutex_lock   = { op = "mutex_lock", object = 1, blocking = "always" }
   os_mutex_unlock = { op = "mutex_unlock", object = 1 }
   os_cond_wait    = { op = "cond_wait", cond = 1, mutex = 2, spurious = true }
   os_task_spawn   = { op = "thread_create", entry = 2, arg = 3, arity = 5 }

   [environment.threads.types]
   os_mutex_t = "mutex"

The operations are ``thread_create``, ``thread_join``, ``thread_detach``,
``thread_self``, ``thread_exit``, ``mutex_init``, ``mutex_lock``,
``mutex_unlock``, ``mutex_destroy``, ``cond_wait``, ``cond_signal``,
``cond_broadcast``, ``tss_create``, ``tss_set``, ``tss_get``, ``tss_delete``,
``once`` and ``sleep``. Each takes only its own roles, and the scan refuses
the manifest otherwise:

- ``thread_create`` must give ``entry``, and may give ``arg`` and ``handle``.
- A ``cond_wait`` must state ``spurious``, whether it can return without a
  signal. CON36-C reports only a wait that can.
- The thread-specific storage operations must give ``key``. For a family
  with fixed slots instead of created keys, as FreeRTOS has, the key is the
  slot index.
- ``arity``, the exact argument count, is optional on every operation. A call
  with another count is a different function of the same name.

A C11 or POSIX name the project defines itself, such as a
``pthread_cond_wait`` shim over another platform's API, is the project's
function: its calls reach that body, in the same file or in any other scanned
file, so they are not the library's operation. A declaration of such a name
under ``functions`` is in force for those calls alone. A call that reaches
the library keeps the library's contract, so declaring a library name the
project does not define changes nothing. A function the selected profile
already covers cannot be declared, nor can a C11 or POSIX type. When a
manifest and the command line both declare one function, they must give it
the same contract.

These tables are facts about the project, so ``--profile`` keeps them and
``--write-config`` writes them. They enter the settings hash only when
something differs from the default.

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

|rules_total| rules are tracked across 17 categories (API, ARR, CON, DCL, ENV,
ERR, EXP, FIO, FLP, INT, MEM, MSC, POS, PRE, SIG, STR, and WIN); |rules_implemented|
are implemented, and |rules_enabled| of those are enabled by default (the other
|rules_withheld| are withheld because they misfire; see `Withheld until rewritten`_
below). The remaining |rules_unimplemented| are tracked but not implemented;
see `Tracked but not implemented`_ below.
``aurora-lint --list-rules`` lists every rule aurora-lint implements, with its
default setting and severity (``--list-rules json`` for tooling). The rule
source files are in ``src/rules/cert_c/``.

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

Removed rules
-------------

A rule aurora-lint no longer ships (ADR-0013: it is unenforceable, fails the
shipping criterion, is covered by another rule, or CERT deprecated it) is
removed from the tool, not disabled. A configuration written for an older
release may still have a ``[rules.cert_c.<ID>]`` block for it. That
configuration still loads: aurora-lint prints one warning naming the release
that removed the rule, why, and which rules cover it, and ignores the block.
``aurora-lint --list-rules`` lists every shipped rule, then every removed
rule with its reason (``--list-rules json`` for tooling). The list is kept in
``rules_templates/removed-rules.toml``.

The rules removed so far:

.. REMOVED-RULES:START

- **CON50-C** (removed in v0.7.0, not a CERT C guideline (C++ id)): CERT C has no CON50-C; it is CERT C++'s CON50-CPP. CON31-C reports a mutex destroyed while locked, and CON34-C an automatic mutex shared with a thread. Now covered by CON31-C, CON34-C.
- **ERR06-C** (removed in v0.7.0, unenforceable): Its checkable form reports every assert in a program that registers an exit handler, which contradicts MSC11-C, and a narrower form needs the programmer's intent.
- **FIO03-C** (removed in v0.7.0, unenforceable): Whether opening a file for writing may replace an existing one is the programmer's intent, which the code does not show; the race on creating a file is FIO45-C's.
- **FIO50-C** (removed in v0.7.0, not a CERT C guideline (C++ id)): CERT C has no FIO50-C; it is CERT C++'s FIO50-CPP. FIO39-C reports the same alternation of input and output on one stream. Now covered by FIO39-C.
- **FIO51-C** (removed in v0.7.0, not a CERT C guideline (C++ id)): CERT C has no FIO51-C; it is CERT C++'s FIO51-CPP. FIO42-C reports the same file left open. Now covered by FIO42-C.
- **FLP05-C** (removed in v0.7.0, fails the criterion): Its checkable form, a constant below the normal minimum of its type, cannot reach CERT's example, where the value is computed at run time.
- **INT14-C** (removed in v0.7.0, fails the criterion): A readability recommendation, whose check reported CERT's own compliant exception for bit-vector serialization.
- **MSC14-C** (removed in v0.7.0, unenforceable): An unnecessary platform dependency has no checkable form; C23 settles CERT's two's-complement example, and the integer rules cover it.
- **MSC42-C** (removed in v0.7.0, moved to CWE ruleset): MSC42-C is not a CERT C identifier; the weak-cipher check is unchanged. Now reported as CWE-327 in the CWE ruleset.
- **POS55-C** (removed in v0.7.0, moved to CWE ruleset): CERT C never published a POS55-C; the socket-ordering check is unchanged. Now reported as CWE-666 in the CWE ruleset.
- **PRE12-C** (removed in v0.7.0, fails the criterion): CERT demoted it to a recommendation: a macro that evaluates a parameter more than once is a matter of style, and the hazard, an argument with side effects, is PRE31-C's.
- **PRE13-C** (removed in v0.7.0, fails the criterion): CERT's noncompliant example is well defined (an undefined macro in #if evaluates to 0), and the check reported a common, correct idiom.
- **STR03-C** (removed in v0.7.0, unenforceable): Whether truncating a string is acceptable is the programmer's intent (CERT's EX1), and CERT marks the rule unenforceable.
- **WIN05-C** (removed in v0.7.0, moved to CWE ruleset): CERT C never published a WIN05-C; its unquoted CreateProcess path check is unchanged, and its registry check now reports only a write under HKEY_LOCAL_MACHINE or HKEY_CLASSES_ROOT, as CWE-272. Now reported as CWE-428 in the CWE ruleset.

.. REMOVED-RULES:END

Withheld until rewritten
------------------------

A rule that misfires, reporting a construct that is not in the code
(ADR-0005), and whose fix is a rewrite of its detection rather than a
correction to it, is withheld until the rewrite, or until its removal when
it is slated for one: it still ships, with its code, but
``enabled = false`` in the default manifest, so a scan with the default
manifest does not run it. Unlike a removed rule, its block loads with no
warning, and ``aurora-lint --list-rules`` lists it as ``off`` among the
shipped rules; its ``disabled_reason`` says it is withheld, and
``--check-config`` and a SARIF export give it. ``--rules`` only narrows the
enabled set, so it does not run a withheld rule, and warns when it names
one. To run one anyway, copy ``rules_templates/rules-all.toml``,
set ``enabled = true`` in the rule's block, and pass the copy with
``--manifest``.

Withheld in v0.7.0, until their rewrites in v0.8.0:

- **EXP30-C** — *Do not depend on the order of evaluation for side effects*
- **FIO01-C** — *Be careful using functions that use file names for identification*
- **FIO08-C** — *Take care when calling remove() on an open file*
- **FIO30-C** — *Exclude user input from format strings*
- **FIO32-C** — *Do not perform operations on devices that are only appropriate for files*
- **FLP32-C** — *Prevent or detect domain and range errors in math functions*
- **INT15-C** — *Use intmax_t or uintmax_t for formatted IO on programmer-defined integer types*
- **MEM35-C** — *Allocate sufficient memory for an object*
- **STR34-C** — *Cast characters to unsigned char before converting to larger integer sizes*
- **WIN30-C** — *Properly pair allocation and deallocation functions*

Withheld in v0.7.0, until its removal, once FIO47-C checks the argument
types it checks:

- **DCL11-C** — *Understand the type issues associated with variadic
  functions*. Its type check guesses an argument's type from its name, so
  it reports a mismatch for an argument whose declared type matches.

Tracked but not implemented
----------------------------

|rules_unimplemented| of the |rules_total| tracked rules have a rule directory and a manifest entry but no
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
