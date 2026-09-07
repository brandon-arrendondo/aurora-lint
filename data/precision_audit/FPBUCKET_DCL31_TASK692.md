# DCL31-C false-positive bucketing (task 692) — COMPLETE

Not a delta-adjudication. No labels were written and none were needed: every
DCL31-C finding in the oracle is already adjudicated FP, so the question was
never "what is the verdict" but "what *causes* the verdict", and that is
answered by reading source, not by adjudicating. Kept in this directory
because it is the same kind of artifact — a pass over a rule's findings whose
conclusions get cited elsewhere and therefore has to be reproducible on
another machine.

Measured 2026-09-07 against realworld run **238** (`sqc-0.4.336-d2ee5ac2`) for
the population, and against a local build at `406a9c02` for the cause
analysis. Read the "Basis" and "Caveats" sections before quoting any number
here.

## Basis

**Every count in this document is distinct `(file, line, rule_id)`**, which is
what `bench_db.db.BenchDB._run_violation_keys` reduces a run to and therefore
what the oracle's own per-rule counts mean. A raw `--export` from the CLI is
*violation rows*, which is a different and larger number — raylib emits 328
rows at 315 distinct keys, because DCL31-C can fire more than once on a line
(`SDL_GL_SetAttribute(...); SDL_GL_SetAttribute(...);` on one line, and
similar). The first version of this bucketing was tabulated on rows and every
figure was ~4% high. Convert before comparing to anything from Postgres.

**None of the local-scan counts are project measurements** and none may be
published (CLAUDE.md, "Where benchmark data lives"). They describe this
checkout's re-scans, whose only purpose is attributing causes. The population
figures — which findings exist, which carry a label — come from Postgres.

## Population (from Postgres, run 238)

`ground_truth` holds **1,713** DCL31-C rows across 8 projects, **all verdict
FP, zero TP**. Run 238 emits **377** findings, of which 337 match an existing
label and 40 are unlabeled.

The two sets have drifted far apart. Findings the oracle labeled but HEAD no
longer produces: hostap 714, curl 337, sel4 136, mosquitto 10, and 146 of
sqlite's 152. What remains is concentrated in one project:

| Project  | run 238 | labeled | unlabeled |
|----------|--------:|--------:|----------:|
| raylib   | 325 | 325 | 0 |
| pureftpd |  39 |   1 | 38 |
| sqlite   |   8 |   6 | 2 |
| lua      |   5 |   5 | 0 |
| **Total**| **377** | **337** | **40** |

So "the 324 labeled FPs" this task was filed against is not the population
that exists today. Anyone re-running this should re-derive the population
first rather than assuming these rows are stable.

## Buckets

Counts are distinct findings from local re-scans **with every include path
supplied** (`-I <src> -I /usr/include --system-includes`), so the
include-coverage variable is held constant and what is left is cause. That
config yields 367 findings against run 238's 377; the 10-finding difference is
exactly the "missing `-I` in runner config" bucket, which the runner still
has and these scans do not.

| n | Bucket | Project | Ours to fix? |
|--:|--------|---------|--------------|
| 280 | Platform SDK header absent on this node | raylib | No — see below |
|  22 | glibc decls behind feature-test macros (`#ifdef __USE_POSIX`) | pureftpd | Yes |
|  20 | `EM_ASM`/`EM_JS` JavaScript bodies parsed as C | raylib | Yes |
|  15 | Unity build: `.c` `#include`d by another `.c` | raylib | Yes |
|  11 | Three declarator-reading gaps | lua, sqlite | Yes |
|  10 | No `-I` in the runner config | pureftpd | Yes (config) |
|   7 | In-file declaration lost past a node threshold | pureftpd | Yes |
|   2 | Inactive `#if` branch; build-generated header | sqlite | Partly |
| **367** | | | |

**89% is not ours.** raylib's `src/platforms/*.c` include their own headers
correctly; the headers are SDL, `windows.h`, emscripten, the Android NDK, EGL
and libdrm, which are not installed here and in the Win32 case cannot be. That
is a statement about this node, not about the rule and not about aurora-lint.
It is why a per-rule precision figure for DCL31-C is uninformative in both
directions, and it does not move with rule work.

Each fixable bucket is filed as its own task in this repo's backlog, linked
from task 692's `Related:` line. Cite them from there — the display ids are
not repeated here on purpose.

## Reproducing

### 1. Population, from Postgres

This repo is Postgres-blind by design, so the query runs from `benchmarking_db`
using its own package and venv. Note the placeholder style: `BenchDB`'s psycopg
shim translates sqlite-style `?`, so `%s` raises "0 placeholders but 1
parameters were passed".

```python
# run with ~/data-enterprise/benchmarking_db/.venv/bin/python
import sys; sys.path.insert(0, '/home/brandon/data-enterprise/benchmarking_db')
from bench_db.db import BenchDB
db = BenchDB()
with db._cursor() as cur:
    cur.execute("select project, verdict, count(*) as n from ground_truth "
                "where rule_id=? group by 1,2 order by 1", ('DCL31-C',))
    for r in cur.fetchall():
        print(dict(r))
```

To join a run's findings to labels, do **not** join on `file_path` in SQL. The
run stores absolute paths (`/home/brandon/toolchain/lua/lauxlib.c`) and
`ground_truth` stores project-relative ones; a naive join silently returns zero
matches, which reads exactly like "nothing is labeled". Normalize in Python
with `db.project_relpath(project, path)` and look labels up via
`db.get_ground_truth_labels(project, commit)`, keyed
`(project, relpath, line)` — the same thing `_run_violation_keys` does.

### 2. Cause analysis, locally

Requires the corpus checkouts from `docs/benchmark-setup.rst` at the pinned
commits (run `python -m bench corpus-check` first) and a release build.

```bash
R=~/toolchain/raylib
target/release/aurora-lint "$R/src" -m conf/realworld/raylib-rules.toml \
  --rules DCL31-C -I "$R/src" -I /usr/include --system-includes \
  --exclude '**/external/**' -e /tmp/raylib_dcl31.json

P=~/toolchain/pureftpd
target/release/aurora-lint "$P" -m conf/realworld/pureftpd-rules.toml \
  --rules DCL31-C -d "$P/src" -d "$P/puredb" \
  -I "$P/src" -I /usr/include --system-includes \
  --exclude 'gui/**' -e /tmp/pureftpd_dcl31.json
```

Run each twice, with and without the include flags, and diff on
`(file, line, function-name-from-message)`. The delta is the
include-coverage bucket; the intersection is everything else. Both arms must
use the *same binary* — the absolute count moves between builds, the delta
does not.

`--system-includes` is worth isolating as its own arm. It is off by default
because it spawns a compiler, and without it glibc's multiarch headers are
unreachable, so `-I /usr/include` alone still misses part of libc on
Debian/Ubuntu — `ioctl` is the visible case here (8 findings).

### 3. Separating "declared nowhere" from "declared somewhere we did not look"

For each function name in the message, search raylib's own tree and the system
include dirs for a declaration. **Match declaration shapes, not the bare name**
— a `grep` for `name\s*\(` matches the call sites themselves, which put every
finding in a "declared in its own file" bucket that means nothing. That error
produced the first, wrong version of this table.

### 4. The node-threshold repro (pureftpd bucket, 7 findings)

`listfile` is defined `static` at `src/ls.c:239` and called at 698, 702, 704,
898, 943. Same file, definition textually first, and DCL31-C's
`track_function_declaration` walks in pre-order — so it should be in
`declared_functions` before the call is visited. It is not, and the trigger is
file size:

```bash
P=~/toolchain/pureftpd
for N in 16 17; do
  { sed -n '1,425p' $P/src/ls.c
    echo "static void filler(void) { unsigned int z = 0;"
    python3 -c "print('    z = z + 1U;\n'*$N)"
    echo "(void)z; }"
    printf '\nvoid __probe(void){ listfile(0,0); }\n'
  } > /tmp/b_$N.c
  echo "N=$N $(wc -c < /tmp/b_$N.c) bytes: \
$(target/release/aurora-lint /tmp/b_$N.c --rules DCL31-C 2>&1 | grep -c listfile)"
done
```

`N=16` → clean (12,101 bytes). `N=17` → flagged (12,117 bytes). A 16-byte,
one-statement difference. Padding with the same volume of *comment* does not
flip it (14,367 bytes, still clean), so it is a node or statement budget, not
a byte or line cap. It reproduces with include paths fully resolvable, so it is
independent of header reachability, and at `N=17` a second name (`logfile`)
starts being flagged too.

Leading suspect, **not confirmed**: `parse_with_recovery` in
`src/analyze/unknown_identifier_recovery.rs` repairs one unknown-identifier
`ERROR` node per iteration and is capped at `MAX_ITERATIONS = 8`; a file with
more unrepairable sites keeps `ERROR` regions in the final tree, and any
declaration inside one is invisible to every rule that walks it. pure-ftpd is a
heavy case because its autoconf-generated `src/config.h` is absent from a fresh
checkout, so many types never resolve. What that hypothesis does *not* yet
explain is why appending statements at the *end* of the file changes which
earlier sites get repaired. Someone should confirm the mechanism before scoping
a fix, because if it is the shared budget then this is not a DCL31-C bug at all.

## Caveats

- **The binary was not exactly HEAD.** `target/release/aurora-lint` was built
  at 13:23 on 2026-09-07, before pulling `406a9c02`, which touched
  `src/analyze/{function_summary,init_state,null_state}.rs`. DCL31-C reads none
  of those, and every comparison here is a diff between two arms sharing one
  binary, so the deltas hold. The absolute 315 does not: run 238's binary
  produces 325 for raylib under a narrower include config, and ~2 of that gap
  is unattributed. Rebuild before treating any absolute here as current.
- **The 40 unlabeled findings were not adjudicated.** 38 are pureftpd, and
  they are bucketed by cause like the rest, but they carry no verdict. If a
  precision claim is ever made about DCL31-C on pureftpd, they need
  delta-adjudication first (CLAUDE.md, protocol step 6).
- **Bucket boundaries are judgement, not measurement.** "SDK header absent"
  and "build-generated header absent" are the same mechanism seen in two
  places, split because the remedies differ. The 89% headline is robust to
  redrawing them; the individual small buckets are not.
