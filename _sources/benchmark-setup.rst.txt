Benchmark Setup
===============

This section covers installing comparison tools, setting up the Juliet test suite,
and configuring real-world codebases for benchmarking.

Benchmark Host Layout
----------------------

Every benchmark node needs one directory -- ``$SQC_BENCH_ROOT`` (default
``~/toolchain``) -- holding the Juliet suite and every real-world codebase
checkout. ``bench/config.py`` and ``bench/realworld_runner.py`` both
read this from the ``SQC_BENCH_ROOT`` environment variable, or from a
``.env`` file at the repo root (copy ``.env.example`` -- it's gitignored, so
each machine sets its own).

To provision a fresh node, run the Ansible playbook (clones and pins all 9
real-world codebases; does not fetch Juliet -- see below):

.. code-block:: bash

    ansible-playbook playbooks/setup-benchmark-repos.yml -i "localhost," -c local
    # Or a different root:
    ansible-playbook playbooks/setup-benchmark-repos.yml -i "localhost," -c local \
      -e bench_root=/data/toolchain

Keep ``bench_root`` and ``SQC_BENCH_ROOT``/``.env`` pointed at the same
directory -- the playbook provisions the checkouts the code actually reads.
A mismatch is easy to miss: if ``SQC_BENCH_ROOT`` is unset and the corpora
do not live in ``~/toolchain``, ``BENCH_ROOT`` silently resolves to a
directory that does not exist. ``python -m bench corpus-check`` reports the
resolved root and says so outright.

Installing Comparison Tools
---------------------------

cppcheck
~~~~~~~~

.. code-block:: bash

    sudo apt update
    sudo apt install -y cppcheck

    # Verify
    cppcheck --version
    # Expected: Cppcheck 2.x.x

For the latest release, build from source:

.. code-block:: bash

    sudo apt install -y cmake libpcre3-dev
    git clone https://github.com/danmar/cppcheck.git
    cd cppcheck
    cmake -DCMAKE_BUILD_TYPE=Release -DUSE_MATCHCOMPILER=ON .
    make -j$(nproc)
    sudo make install

clang-tidy
~~~~~~~~~~

**Pin LLVM 21 — do not take the distro default.**  Ubuntu 24.04 ships
clang-tidy 18.1.3 and tops out at 20, while the published comparison in
``docs/tool-comparison.rst`` is LLVM 21.1.  Taking the distro package makes a
freshly-provisioned node measure an *older* competitor than the table it will
be compared against, and clang-tidy is the tool currently beating SqC on the
Juliet overlap (99.2% vs 81.7%) — so that regression would flatter SqC by
understating a rival.  ``playbooks/install-static-analyzers.yml`` does this
automatically; by hand:

.. code-block:: bash

    sudo install -d -m 0755 /etc/apt/keyrings
    wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key \
      | sudo tee /etc/apt/keyrings/apt.llvm.org.asc > /dev/null
    echo "deb [signed-by=/etc/apt/keyrings/apt.llvm.org.asc] \
      http://apt.llvm.org/noble/ llvm-toolchain-noble-21 main" \
      | sudo tee /etc/apt/sources.list.d/llvm-21.list
    sudo apt update && sudo apt install -y clang-tidy-21
    sudo update-alternatives --install /usr/bin/clang-tidy clang-tidy \
      /usr/bin/clang-tidy-21 100

    # Verify
    clang-tidy --version
    # Expected: Ubuntu LLVM version 21.1.x

The distro package is fine for anything that is not a published comparison:

.. code-block:: bash

    sudo apt install -y clang clang-tidy

bear (for compile_commands.json)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Required for clang-tidy on projects with build systems:

.. code-block:: bash

    sudo apt install -y bear

Facebook Infer
~~~~~~~~~~~~~~

Infer v1.2.0 is installed from prebuilt Linux binaries.  The playbook at
``playbooks/install-static-analyzers.yml`` automates this:

.. code-block:: bash

    ansible-playbook playbooks/install-static-analyzers.yml \
      -i "localhost," -c local --ask-become-pass

Manual install:

.. code-block:: bash

    # libtinfo5 required (Infer links against libtinfo.so.5)
    sudo apt install -y libtinfo5 || \
      sudo ln -s /usr/lib/x86_64-linux-gnu/libtinfo.so.6 \
                  /usr/lib/x86_64-linux-gnu/libtinfo.so.5

    VERSION=1.2.0
    curl -sSL "https://github.com/facebook/infer/releases/download/v$VERSION/infer-linux-x86_64-v$VERSION.tar.xz" \
      | sudo tar -C /opt -xJ
    sudo ln -s "/opt/infer-linux-x86_64-v$VERSION/bin/infer" /usr/local/bin/infer

    # Verify
    infer --version
    # Expected: Infer version v1.2.0

Frama-C
~~~~~~~

Frama-C is installed via opam (the Debian 12 apt package is version 25/Manganese,
too old for benchmarking).  The playbook handles this automatically.

Manual install:

.. code-block:: bash

    sudo apt install -y opam gcc g++ make m4 pkg-config autoconf \
      libgmp-dev zlib1g-dev libgtk-3-dev libgtksourceview-3.0-dev graphviz

    opam init --bare --no-setup --disable-sandboxing
    opam switch create default 4.14.2
    eval $(opam env)
    opam install -y frama-c

    # Verify (requires eval $(opam env) in each shell session)
    frama-c -version
    # Expected: 33.0 (Arsenic) as of 2026-09-04; 32.0 (Germanium) is what the
    # competitor Juliet runs in data/competitor_results/ were taken with

.. note::

    Add ``eval $(opam env)`` to your shell profile (``~/.bashrc``) to make
    ``frama-c`` available without manual activation.  The benchmark runner
    does not need it: ``bench/realworld_runner.py`` wraps every Frama-C
    invocation in ``eval $(opam env)`` itself, because it is not a login
    shell.

.. warning::

    Frama-C renamed the compile-database option between the two versions
    above — ``-json-compilation-database`` through 32.0, ``-compilation-db``
    from 33.0.  The runner probes ``frama-c -kernel-h`` and picks whichever
    the installed binary accepts, so both work; a hand-written command line
    copied from an older doc will abort with "option is unknown".

Build-based tools need a compile database
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Infer and Frama-C cannot be pointed at a source tree the way sqc and cppcheck
can — both need a real preprocess.  On the real-world suite they are driven
from each checkout's ``compile_commands.json``, so
``playbooks/setup-compile-commands.yml`` must have run for a codebase before
either tool can scan it.  ``python -m bench realworld-run --tool infer`` fails
fast with the exact command to fix it if the database is missing.

Expect a *partial* result from both, and check the ``coverage`` block each run
writes:

- **Infer** captures whatever preprocesses.  ``setup-compile-commands.yml``
  restores each checkout to pristine after building it, which deletes the
  build's generated headers while leaving the compile database that still
  references them — libcrc's ``tab/gentab32.inc`` is the worked example, and
  2 of its 9 in-scope translation units cannot be captured as a result.
- **Frama-C** is partial by construction, because EVA analyses one entry
  point at a time and a real codebase has no single one.  Read
  ``docs/design/framac-realworld.md`` before quoting any Frama-C real-world
  number: a finding count from it is a floor, and recall is not expressible
  from it at all.

Juliet Test Suite Setup
-----------------------

NIST SARD is a click-through portal with no stable direct-download URL, so
this step is manual (the setup playbook only creates the parent directory
and reports whether the suite is already in place). Download the `NIST
Juliet Test Suite v1.3 <https://samate.nist.gov/SARD/test-suites/112>`_:

.. code-block:: bash

    mkdir -p $SQC_BENCH_ROOT/benchmarks   # default: ~/toolchain/benchmarks
    cd $SQC_BENCH_ROOT/benchmarks
    # Download and extract juliet-test-suite-c
    # Expected structure:
    #   juliet-test-suite-c/testcases/CWE*/     (118 CWE directories)
    #   juliet-test-suite-c/testcasesupport/    (shared helper functions)

Third-Party Library Headers
---------------------------

SqC uses ``-I`` include paths to resolve ``#include`` directives from third-party
libraries. Without these, functions declared in external headers produce
DCL31-C/DCL07-C false positives.

.. code-block:: bash

    # Core dependencies (covers most projects)
    sudo apt-get install -y \
      libssl-dev libcjson-dev zlib1g-dev

    # mosquitto
    sudo apt-get install -y libcunit1-dev libsqlite3-dev

    # curl TLS backends
    sudo apt-get install -y libmbedtls-dev libgnutls28-dev

    # sqlite test infrastructure
    sudo apt-get install -y tcl-dev

    # hostap
    sudo apt-get install -y \
      libnl-3-dev libnl-genl-3-dev libdbus-1-dev \
      libgcrypt20-dev libpcap-dev libwolfssl-dev

One-liner for all hosts:

.. code-block:: bash

    sudo apt-get install -y libssl-dev libcjson-dev zlib1g-dev libcunit1-dev \
      libsqlite3-dev libmbedtls-dev libgnutls28-dev tcl-dev libnl-3-dev \
      libnl-genl-3-dev libdbus-1-dev libgcrypt20-dev libpcap-dev libwolfssl-dev

Per-Project Include Paths
~~~~~~~~~~~~~~~~~~~~~~~~~

The real-world runner passes these automatically via the ``includes`` field in
each codebase's config:

===========  ============================================  ============================
Project      ``-I`` Paths                                  Resolves
===========  ============================================  ============================
libcrc       *(none)*                                      Pure C, no external deps
sqlite       ``/usr/include``                              OpenSSL, zlib, Tcl
mosquitto    ``/usr/include``, ``/usr/include/cjson``      OpenSSL, cJSON, CUnit, sqlite3
curl         ``/usr/include``, ``{path}/lib``              OpenSSL, mbedTLS, GnuTLS
hostap       ``/usr/include``, ``/usr/include/libnl3``,    OpenSSL, wolfSSL, libnl,
             ``/usr/include/dbus-1.0``                     D-Bus, libgcrypt, libpcap
===========  ============================================  ============================

Real-World Project Setup
------------------------

Pinned Source Commits
~~~~~~~~~~~~~~~~~~~~~

All benchmark results are run against these exact commits -- the full set of
projects in ``bench/realworld_runner.py``'s ``CODEBASES`` registry
(which stores paths and per-tool flags, not the pins).

.. note::

    The **single source of truth for the pins is**
    ``data/benchmark_repos.json``. Both
    ``playbooks/setup-benchmark-repos.yml`` (provisioning) and ``python -m
    bench corpus-check`` (verification) read it. The table below is a
    human-readable mirror -- if the two disagree, the JSON wins. Do not add
    a third copy.

Each checkout must sit at a **detached HEAD** on its pinned commit. A
checkout left on a tracking branch is not pinned even while it happens to
match: the next ``git pull`` moves it silently, and every finding then lands
at ``(file, line)`` pairs the ``ground_truth`` oracle -- keyed on
project+commit+file+line+rule -- was never adjudicated against, so it drops
out of the precision/recall denominator without any error. This is not
hypothetical; see `Verifying the Pins`_ below.

.. list-table::
   :header-rows: 1
   :widths: 12 40 38 10

   * - Project
     - Repository
     - Commit SHA
     - Checkout state
   * - libcrc
     - https://github.com/lammertb/libcrc
     - ``7719e2112a9a960b1bba130d02bebdf58e8701f1``
     - detached
   * - sqlite
     - https://github.com/sqlite/sqlite.git
     - ``b1a73ba34d05b32007315e4065c6468cc638e3af``
     - detached
   * - mosquitto
     - https://github.com/eclipse-mosquitto/mosquitto
     - ``d3ee5c5ca62c0fa4983308c6fff558ee978e878c``
     - detached
   * - curl
     - https://github.com/curl/curl.git
     - ``3e198f75861cc2e12daf299689e145949dddd19b``
     - detached
   * - hostap
     - https://git.w1.fi/hostap.git
     - ``dcee60436390dd34731560657c4257c3b4c839a6``
     - detached
   * - lua
     - https://github.com/lua/lua.git
     - ``40b76de2d77e66b70a9d4bf989c3f5340919973f``
     - detached
   * - raylib
     - https://github.com/raysan5/raylib.git
     - ``962bbfc6bfbd7a5acd08e21314fcfa161003a589``
     - detached
   * - pureftpd
     - https://github.com/jedisct1/pure-ftpd.git
     - ``cc28bff52ca28e1d122a2142bf37f2dc578f4d3e``
     - detached
   * - sel4
     - https://github.com/seL4/seL4.git
     - ``1326364bc9135d9445d936ebc01e38a402c1f4c6``
     - detached

.. important::

    ``pureftpd``'s checkout directory must be named ``pureftpd`` (no
    hyphen), not the upstream ``pure-ftpd`` -- two path-parsing spots in
    ``bench/db.py`` (result-filename parsing, ground-truth path
    normalization) require the checkout dir basename to match the registry
    key exactly. The playbook already clones it to the right name.

Verifying the Pins
~~~~~~~~~~~~~~~~~~

Provisioning pins the checkouts once; nothing kept them pinned. Run this
before any real-world benchmark or precision claim:

.. code-block:: bash

    python -m bench corpus-check          # exits 1 if anything is off
    python -m bench corpus-check --json   # machine-readable

It reports one row per project, worst first:

===========  =========================================================
Status       Meaning
===========  =========================================================
MISSING      Checkout directory absent
NOT_GIT      Directory exists but is not a git checkout
PIN_ABSENT   Pinned commit not present locally (needs a fetch)
DRIFTED      ``HEAD`` is not the pinned commit
UNPINNED     ``HEAD`` matches the pin but sits on a branch, so the next
             ``git pull`` silently drifts it
OK           Detached at the pinned commit
===========  =========================================================

It also flags three contamination cases independent of status:

* tracked files modified, so the scanned source is not the pin;
* **untracked ``*.c``/``*.h`` files, which sqc will scan** and attribute to
  the pinned commit (untracked files sqc ignores are counted separately and
  are harmless);
* **gitignored ``*.c``/``*.h`` files**, which are invisible to ``git
  status`` but which sqc scans anyway -- it dispatches on file extension and
  never consults git. The case to watch is a build run inside a checkout:
  sqlite's build generates a gitignored ``sqlite3.c`` amalgamation, which
  would silently add ~250k lines to every sqlite scan.

.. tip::

    Keep the checkouts pristine. Build artifacts belong in a separate tree,
    not inside ``$SQC_BENCH_ROOT``.

.. warning::

    This check exists because the failure is silent and did happen. On the
    work node curl, hostap and sqlite had all drifted, while libcrc and lua
    sat on tracking branches matching their pins only by coincidence. A gate
    run against the drifted trees reported hostap 452 / sqlite 516 findings
    where the pinned snapshots give 447 / 506 -- close enough to look
    plausible, and not comparable to ``ground_truth`` at all. Fix drift with
    the ``git checkout --detach`` command the check prints for each row.

Clone and Pin
~~~~~~~~~~~~~

Preferred: run ``playbooks/setup-benchmark-repos.yml`` (see `Benchmark Host
Layout`_ above) -- it clones, pins, and verifies all 9 checkouts in one pass,
reading the pins from ``data/benchmark_repos.json``.

Manual fallback:

.. code-block:: bash

    mkdir -p $SQC_BENCH_ROOT   # default: ~/toolchain
    cd $SQC_BENCH_ROOT

    git clone https://github.com/lammertb/libcrc.git
    cd libcrc && git checkout 7719e2112a9a960b1bba130d02bebdf58e8701f1 && cd ..

    git clone https://github.com/sqlite/sqlite.git
    cd sqlite && git checkout b1a73ba34d05b32007315e4065c6468cc638e3af && cd ..

    git clone https://github.com/eclipse-mosquitto/mosquitto.git
    cd mosquitto && git checkout d3ee5c5ca62c0fa4983308c6fff558ee978e878c && cd ..

    git clone https://github.com/curl/curl.git
    cd curl && git checkout 3e198f75861cc2e12daf299689e145949dddd19b && cd ..

    git clone https://git.w1.fi/hostap.git
    cd hostap && git checkout dcee60436390dd34731560657c4257c3b4c839a6 && cd ..

    git clone https://github.com/lua/lua.git
    cd lua && git checkout 40b76de2d77e66b70a9d4bf989c3f5340919973f && cd ..

    git clone https://github.com/raysan5/raylib.git
    cd raylib && git checkout 962bbfc6bfbd7a5acd08e21314fcfa161003a589 && cd ..

    # NOTE: checkout dir must be "pureftpd" (no hyphen) -- see the warning above
    git clone https://github.com/jedisct1/pure-ftpd.git pureftpd
    cd pureftpd && git checkout cc28bff52ca28e1d122a2142bf37f2dc578f4d3e && cd ..

    # NOTE: checkout dir must be lowercase "sel4" to match the registry key
    git clone https://github.com/seL4/seL4.git sel4
    cd sel4 && git checkout 1326364bc9135d9445d936ebc01e38a402c1f4c6 && cd ..

Running Each Tool Manually
--------------------------

.. note::

    The examples below use an illustrative ``~/data/comparisons/<project>``
    checkout path for ad hoc manual runs. If you provisioned codebases via
    ``playbooks/setup-benchmark-repos.yml``, substitute
    ``$SQC_BENCH_ROOT/<project>`` (default ``~/toolchain/<project>``) instead
    -- that's the path ``bench/realworld_runner.py`` itself reads.

sqc
~~~

.. code-block:: bash

    # Build
    cd ~/data/tools_sqc
    cargo build --release

    # Basic run
    ./target/release/sqc /path/to/source/ --export results.json

    # With cross-file context
    ./target/release/sqc /path/to/source/ -d /path/to/source/ --export results.json

    # When running from outside the sqc repo, pass --manifest explicitly
    ./target/release/sqc /path/to/source/ \
      --manifest ~/data/tools_sqc/rules_templates/rules-benchmark.toml \
      --export results.json

cppcheck
~~~~~~~~

.. code-block:: bash

    cppcheck --enable=all --std=c11 --xml --xml-version=2 \
      --suppress=missingIncludeSystem \
      -I /path/to/include \
      /path/to/source/ \
      2> results.xml

.. warning::

    - cppcheck writes XML to **stderr**, not stdout
    - Never pass ``-I /usr/include`` -- causes parse errors in system headers
    - ``--addon=cert`` is not available on Ubuntu 24.04; ``--enable=all`` includes CERT checks

clang-tidy
~~~~~~~~~~

.. code-block:: bash

    # Option A: With compile_commands.json (recommended)
    cd /path/to/project
    make clean && bear -- make -j$(nproc)
    run-clang-tidy -checks='-*,cert-*,clang-analyzer-*' -p .

    # Option B: Direct file scan (no build required)
    find /path/to/source/ -name '*.c' | \
      xargs -P $(nproc) -I{} clang-tidy \
        -checks='-*,cert-*,clang-analyzer-*' \
        {} -- -std=c11 -I /path/to/include

.. warning::

    - ``bear`` requires ``make clean`` first -- it only captures invocations during an actual build
    - Verify ``compile_commands.json`` is non-empty before running clang-tidy

Per-Project Commands
--------------------

libcrc
~~~~~~

.. code-block:: bash

    # sqc
    ~/data/tools_sqc/target/release/sqc ~/data/comparisons/libcrc \
      -d ~/data/comparisons/libcrc \
      --manifest ~/data/tools_sqc/rules_templates/rules-benchmark.toml \
      --export ~/data/comparisons/results/sqc/libcrc/results.json

    # cppcheck
    cppcheck --enable=all --std=c11 --xml --xml-version=2 \
      --suppress=missingIncludeSystem \
      -I ~/data/comparisons/libcrc/include \
      ~/data/comparisons/libcrc/src/ \
      2> ~/data/comparisons/results/cppcheck/libcrc/results.xml

    # clang-tidy
    cd ~/data/comparisons/libcrc && make clean && bear -- make
    run-clang-tidy -checks='-*,cert-*,clang-analyzer-*' -p . \
      2>&1 | tee ~/data/comparisons/results/clang-tidy/libcrc/results.txt

sqlite
~~~~~~

.. code-block:: bash

    # sqc
    ~/data/tools_sqc/target/release/sqc ~/data/comparisons/sqlite \
      -d ~/data/comparisons/sqlite \
      --manifest ~/data/tools_sqc/rules_templates/rules-benchmark.toml \
      --export ~/data/comparisons/results/sqc/sqlite/results.json

    # cppcheck
    cppcheck --enable=all --std=c11 --xml --xml-version=2 \
      --suppress=missingIncludeSystem \
      -I ~/data/comparisons/sqlite/src \
      ~/data/comparisons/sqlite/src/ \
      2> ~/data/comparisons/results/cppcheck/sqlite/results.xml

    # clang-tidy
    cd ~/data/comparisons/sqlite && ./configure && make clean && bear -- make -j$(nproc)
    run-clang-tidy -checks='-*,cert-*,clang-analyzer-*' -p . \
      2>&1 | tee ~/data/comparisons/results/clang-tidy/sqlite/results.txt

mosquitto
~~~~~~~~~

.. code-block:: bash

    # sqc
    ~/data/tools_sqc/target/release/sqc ~/data/comparisons/mosquitto \
      -d ~/data/comparisons/mosquitto \
      --manifest ~/data/tools_sqc/rules_templates/rules-benchmark.toml \
      --export ~/data/comparisons/results/sqc/mosquitto/results.json

    # cppcheck
    cppcheck --enable=all --std=c11 --xml --xml-version=2 \
      --suppress=missingIncludeSystem \
      -I ~/data/comparisons/mosquitto/include \
      -I ~/data/comparisons/mosquitto/common \
      -i ~/data/comparisons/mosquitto/deps \
      ~/data/comparisons/mosquitto/lib/ ~/data/comparisons/mosquitto/src/ \
      2> ~/data/comparisons/results/cppcheck/mosquitto/results.xml

    # clang-tidy
    cmake -S ~/data/comparisons/mosquitto -B ~/data/comparisons/mosquitto/build \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DWITH_TLS=OFF -DWITH_WEBSOCKETS=OFF -DWITH_TESTS=OFF
    cmake --build ~/data/comparisons/mosquitto/build --clean-first -j$(nproc)
    run-clang-tidy -checks='-*,cert-*,clang-analyzer-*' \
      -p ~/data/comparisons/mosquitto/build \
      2>&1 | tee ~/data/comparisons/results/clang-tidy/mosquitto/results.txt

curl
~~~~

.. code-block:: bash

    # sqc
    ~/data/tools_sqc/target/release/sqc ~/data/comparisons/curl \
      -d ~/data/comparisons/curl \
      --manifest ~/data/tools_sqc/rules_templates/rules-benchmark.toml \
      --export ~/data/comparisons/results/sqc/curl/results.json

    # cppcheck
    cppcheck --enable=all --std=c11 --xml --xml-version=2 \
      --suppress=missingIncludeSystem \
      -I ~/data/comparisons/curl/include -I ~/data/comparisons/curl/lib \
      ~/data/comparisons/curl/lib/ ~/data/comparisons/curl/src/ \
      2> ~/data/comparisons/results/cppcheck/curl/results.xml

    # clang-tidy
    cmake -S ~/data/comparisons/curl -B ~/data/comparisons/curl/build \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DBUILD_SHARED_LIBS=OFF \
      -DCURL_USE_OPENSSL=OFF -DCURL_DISABLE_LDAP=ON \
      -DUSE_LIBIDN2=OFF -DUSE_NGHTTP2=OFF -DCURL_ZSTD=OFF
    cmake --build ~/data/comparisons/curl/build --clean-first -j$(nproc)
    run-clang-tidy -checks='-*,cert-*,clang-analyzer-*' \
      -p ~/data/comparisons/curl/build \
      2>&1 | tee ~/data/comparisons/results/clang-tidy/curl/results.txt

hostap
~~~~~~

.. code-block:: bash

    # sqc
    ~/data/tools_sqc/target/release/sqc ~/data/comparisons/hostap \
      -d ~/data/comparisons/hostap/src \
      -d ~/data/comparisons/hostap/wpa_supplicant \
      --manifest ~/data/tools_sqc/rules_templates/rules-benchmark.toml \
      --export ~/data/comparisons/results/sqc/hostap/results.json

    # cppcheck
    cppcheck --enable=all --std=c11 --xml --xml-version=2 \
      --suppress=missingIncludeSystem \
      -I ~/data/comparisons/hostap/src \
      -I ~/data/comparisons/hostap/src/utils \
      -I ~/data/comparisons/hostap/src/common \
      ~/data/comparisons/hostap/src/ ~/data/comparisons/hostap/wpa_supplicant/ \
      2> ~/data/comparisons/results/cppcheck/hostap/results.xml

    # clang-tidy (requires .config for wpa_supplicant)
    cd ~/data/comparisons/hostap/wpa_supplicant
    cat > .config <<'EOF'
    CONFIG_DRIVER_NL80211=y
    CONFIG_LIBNL32=y
    CONFIG_IEEE8021X_EAPOL=y
    CONFIG_EAP_MD5=y
    EOF
    make clean 2>/dev/null; bear -- make -j$(nproc) wpa_supplicant 2>/dev/null || true
    cd ~/data/comparisons/hostap
    python3 gen_compile_commands.py -o compile_commands.json wpa_supplicant/
    run-clang-tidy -checks='-*,cert-*,clang-analyzer-*' -p . \
      2>&1 | tee ~/data/comparisons/results/clang-tidy/hostap/results.txt

Verifying Results
-----------------

.. code-block:: bash

    PROJECT=libcrc
    RESULTS=~/data/comparisons/results

    echo "=== sqc ==="
    python3 -c "
    import json, collections
    data = json.load(open('$RESULTS/sqc/$PROJECT/results.json'))
    rules = collections.Counter(v['rule_id'] for v in data)
    print(f'Total: {len(data)} findings, {len(rules)} rules')
    for r, c in rules.most_common(10): print(f'  {r}: {c}')
    "

    echo "=== cppcheck ==="
    python3 -c "
    import xml.etree.ElementTree as ET, collections
    errors = ET.parse('$RESULTS/cppcheck/$PROJECT/results.xml').getroot().findall('.//error')
    ids = collections.Counter(e.get('id') for e in errors)
    print(f'Total: {len(errors)} findings')
    for i, c in ids.most_common(10): print(f'  {i}: {c}')
    "

    echo "=== clang-tidy ==="
    grep -c "warning:\|error:" $RESULTS/clang-tidy/$PROJECT/results.txt

Known Pitfalls
~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - Pitfall
     - Symptom
     - Fix
   * - sqc manifest not found
     - ``Failed to read manifest file``
     - Pass ``--manifest`` with absolute path
   * - cppcheck ``--addon=cert`` missing
     - ``Did not find addon cert.py``
     - Remove it; ``--enable=all`` includes CERT
   * - cppcheck ``-I /usr/include``
     - ``syntaxError`` in stdlib.h
     - Never pass system include paths to cppcheck
   * - Empty compile_commands.json
     - clang-tidy shows no diagnostics
     - Run ``make clean`` before ``bear -- make``

Output Format Reference
-----------------------

**cppcheck XML (v2)**:

.. code-block:: xml

    <error id="bufferAccessOutOfBounds" severity="error"
           msg="Array 'arr[10]' accessed at index 10..." cwe="788">
      <location file="example.c" line="5" column="5"/>
    </error>

**clang-tidy text**::

    example.c:5:5: warning: ... [cert-arr30-c]

**sqc JSON**:

.. code-block:: json

    [{"rule_id": "ARR30-C", "severity": "High", "file": "example.c", "line": 5, "message": "..."}]

**sqc SARIF**: SARIF 2.1.0 compatible output with ``ruleId`` matching CERT C rule IDs.

**Infer JSON** (``infer-out/report.json``):

.. code-block:: json

    [{"bug_type": "NULLPTR_DEREFERENCE", "procedure": "func_bad",
      "file": "test.c", "line": 26, "severity": "ERROR"}]

**Frama-C EVA** (stderr, no structured output):

::

    [eva:alarm] test.c:26: Warning:
      out of bounds read. assert \valid_read(&ptr->field);
    assertion 'Eva,mem_access' got final status invalid.

Distributed Benchmarking with GNU Parallel
-------------------------------------------

For fast re-benchmarking across multiple machines after rule changes. Cppcheck and
clang-tidy results are stable across sqc changes -- run them once and cache. Only
sqc needs re-running.

.. code-block:: bash

    # Prerequisites
    sudo apt install -y parallel
    parallel --citation <<< "will cite" 2>/dev/null || true

    # SSH key setup
    ssh-keygen -t ed25519 -f ~/.ssh/id_benchmark -N ""
    for node in node1 node2 node3 node4; do
      ssh-copy-id -i ~/.ssh/id_benchmark.pub $node
    done

Node file (``~/.benchmark_nodes``)::

    user@node1/8
    user@node2/8
    user@node3/8
    user@node4/8

Fast re-benchmark workflow:

.. code-block:: bash

    # 1. Rebuild sqc
    cd ~/data/tools_sqc && cargo build --release

    # 2. Push binary to nodes (if no shared FS)
    parallel --sshloginfile $NODES_FILE --nonall \
      "rsync -az $SQC_BIN {}/sqc_bin"

    # 3. Generate CWE list
    find $JULIET_DIR -maxdepth 1 -type d -name 'CWE*' | sort > /tmp/cwe_dirs.txt

    # 4. Run in parallel across nodes
    parallel --sshloginfile $NODES_FILE -a /tmp/cwe_dirs.txt \
      "$SQC_BIN {} -d $JULIET_DIR -d $JULIET_SUPPORT \
        --export $RESULTS_DIR/sqc/juliet/{/.}.csv"

Exporting competitor results for ingest
---------------------------------------

``bench/competitors.py`` writes one JSON blob per run into
``data/competitor_results/``, and those blobs are committed — they are the
archival form and should not be edited or deleted.  They are not, however,
ingestible: the shape is nested and the per-CWE map is keyed by CWE id, so a
loader would have to know that module's internal layout to read it.

``python -m bench competitor-export`` flattens every run JSON in that
directory into three CSVs beside them:

.. code-block:: text

    competitor_runs.csv         one row per run       (tool, version, totals)
    competitor_cwe_results.csv  one row per run × CWE (the measurements)
    competitor_cwe_errors.csv   one row per error     (usually empty)

``run_key`` joins them and is the JSON's own basename (e.g.
``framac_20260403_222053``), so it is unique, stable across re-exports, and
traceable back to the file it came from.

**Run the export after every competitor benchmark and commit the result.**
The benchmark host ingests these CSVs into ``sqc_bench``; a table missing its
newest run looks exactly like a run that never happened.
``python -m bench competitor-export --check`` exits nonzero if the CSVs are
stale, and writes nothing.

This repo stays Postgres-blind — no DSN, no connection code (see
``CLAUDE.md``).  It *emits* a flat, diffable table; ``benchmarking_db`` owns
the ingest, so nothing here changes when the target schema does.  The CSVs
are a transport, not a source of truth: Postgres remains the only place an
official number comes from, and re-exporting is idempotent and lossless with
respect to the JSON.

.. note::

    The ``hostname`` column is blank for every run recorded before
    2026-09-04, which is all four April runs.  Wall clock is
    hardware-dependent, so a blank means "do not compare this run's duration
    against another host's", not "same host".
