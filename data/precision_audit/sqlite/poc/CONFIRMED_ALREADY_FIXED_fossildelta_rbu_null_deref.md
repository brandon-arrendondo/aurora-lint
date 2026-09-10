# Confirmed real, already fixed upstream — fossildelta.c / sqlite3rbu.c zero-length-blob NULL deref

Found: 2026-09-10, bmdb task 1107 delta-adjudication (EXP34-C, commit `d0802e08`/"1099")
Confirmed and reproduced: 2026-09-10, r720
Status: **NOT a disclosure candidate — already fixed upstream before the pinned oracle
commit was adjudicated.** No forum post drafted. Documented here for the oracle's own
record, per this project's existing precedent for the session/changeset OOB-read
(see this README's "UPDATE (2026-06-12): the changeset OOB-read is CONFIRMED REAL and
already fixed upstream" section).
Artifacts: `poc/fossildelta_zerolen_poc.c`, `poc/fossildelta_zerolen_gdb.txt`,
`poc/rbu_fossildelta_poc.c`, `poc/rbu_fossildelta_gdb.txt`

---

## The defect (as it existed in the pinned oracle commit `b1a73ba34d`, 2026-02-24)

`ext/misc/fossildelta.c`'s `deltaGetInt()` walked its input with no length bound at all:

    static unsigned int deltaGetInt(const char **pz, int *pLen){
      ...
      unsigned char *z = (unsigned char*)*pz;
      unsigned char *zStart = z;
      while( (c = zValue[0x7f&*(z++)])>=0 ){
         v = (v<<6) + c;
      }
      ...
    }

`*pLen` is never consulted inside the loop — it only walks memory until it happens to
land on a byte whose `zValue` lookup is negative. `ext/rbu/sqlite3rbu.c`'s
`rbuDeltaGetInt()` carried an identical, independently-copied loop.

`deltaOutputSizeFunc()` (the `delta_output_size(D)` SQL function) guards a SQL-NULL
argument (`sqlite3_value_type(argv[0])==SQLITE_NULL`) but **not** a zero-length,
non-NULL BLOB — and `sqlite3_value_blob()` returns NULL for *any* zero-length blob
regardless of SQL-NULL-ness (`vdbeapi.c`: `return p->n ? p->z : 0;`). So
`SELECT delta_output_size(x'')` reaches `deltaGetInt()` with `aDelta=NULL,
nDelta=0`, which dereferences NULL unconditionally — before `*pLen` (already 0)
is ever checked.

`ext/rbu/sqlite3rbu.c`'s `rbuFossilDeltaFunc()` (`rbu_fossil_delta(X,D)`) is worse:
it has **no SQL-NULL guard at all** on either argument. `SELECT rbu_fossil_delta(x'00',
NULL)` reaches `rbuDeltaOutputSize()` with the same `aDelta=NULL, nDelta=0` shape.

## Reproduced (GDB, against the pinned commit's exact code, copied verbatim)

Both PoCs isolate the vulnerable function bodies from the pinned checkout
(`~/toolchain/sqlite` @ `b1a73ba34d05b32007315e4065c6468cc638e3af`) into standalone
drivers, called exactly as `deltaOutputSizeFunc`/`rbuFossilDeltaFunc` would for the
SQL statements above:

    $ gcc -O0 -g -o repro poc/fossildelta_zerolen_poc.c
    $ gdb -batch -ex run -ex bt --args ./repro
    Program received signal SIGSEGV, Segmentation fault.
    deltaGetInt (...) at fossildelta_zerolen_poc.c:38
    #0  deltaGetInt (...) at fossildelta_zerolen_poc.c:38
    #1  0x... in delta_output_size (zDelta=0x0, lenDelta=0) at fossildelta_zerolen_poc.c:50
    #2  0x... in main () at fossildelta_zerolen_poc.c:66

    $ gcc -O0 -g -o repro poc/rbu_fossildelta_poc.c
    $ gdb -batch -ex run -ex bt --args ./repro
    Program received signal SIGSEGV, Segmentation fault.
    rbuDeltaGetInt (...) at rbu_fossildelta_poc.c:30
    #0  rbuDeltaGetInt (...) at rbu_fossildelta_poc.c:30
    #1  0x... in rbuDeltaOutputSize (zDelta=0x0, lenDelta=0) at rbu_fossildelta_poc.c:42
    #2  0x... in main () at rbu_fossildelta_poc.c:59

Both crash exactly where predicted, on the first dereference inside the loop.

## Already fixed upstream

Checked against `~/data-enterprise/sqlite-main` (tracks trunk, currently `b1df30c735`,
2026-08-25 — postdates the pinned oracle commit by ~6 months). Trunk's `deltaGetInt()`/
`rbuDeltaGetInt()` both now bound the walk against `*pLen`:

    unsigned char *zEnd = z + (*pLen);
    while( z<zEnd && (c = zValue[*z])>=0 ){
      v = (v<<6) + c;
      z++;
    }

With `*pLen==0`, `z<zEnd` is false on the first check, the loop body never runs, and
`delta_output_size`'s subsequent `lenDelta<=0` check short-circuits before `*zDelta`
is ever read — confirmed empirically: `poc/fossildelta_zerolen_fixed_repro` (built
from the trunk version, not checked into `poc/` — reproducible from this doc) returns
`-1` cleanly with no crash.

Fixing commits, both between the pinned commit and trunk HEAD:

- **`84ead09d94`** (2026-06-10) — "Harden code that processes Fossil Deltas against
  OOM and maliciously malformed delta blobs." References two bug reports dated
  2026-06-10, i.e. reported and fixed independently of this project.
- **`2f13a51628`** (2026-07-04) — "Fix possible one-byte OOB read in the
  fossildelta.c extension."
- **`1b2a4a37b0`** (2026-07-06) — "Reduce divergence between ext/misc/fossildelta.c,
  the delta code in ext/rbu/sqlite3rbu.c, and Fossil itself" — this is the commit that
  propagated the `zEnd`-bounded loop from `fossildelta.c` into `sqlite3rbu.c`'s
  independent copy, closing the `rbu_fossil_delta()` path too.

## What this means for the ground_truth labels

Both TP verdicts (`sqlite/ext/misc/fossildelta.c:683,721` and
`sqlite/ext/rbu/sqlite3rbu.c:721`, source `task1107_delta_exp34_sqlite_b3` /
`task1107_delta_exp34_sqlite_b4`) are **confirmed conclusively**, not just
plausible — corroborated by an independent, external fix history rather than only
by reading the pinned-commit source. This is the same standard of evidence the
suite already uses for FN provenance tags (`cve:`, `cross:`) — an upstream fix is
strong outside corroboration a code-reading verdict alone doesn't have.

Per the disclosure philosophy (triple-verify before filing, check for prior art),
this does **not** get drafted as a forum post: the bug is dead at trunk HEAD, so a
disclosure would report something already fixed. Recorded here instead, matching
the session/changeset OOB-read precedent elsewhere in this README.
