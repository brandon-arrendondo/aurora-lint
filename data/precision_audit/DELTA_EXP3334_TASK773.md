# EXP33-C/EXP34-C delta-adjudication (bmdb task 773) — batch complete

Delta-adjudication for bmdb task 773 (the tools_sqc output-parameter cluster,
1025-1029 / commits 045320bc + c96b32a7, plus tools_sqc 1065's bug #4 fix at
`fd6d964a`) against real-world run 244 (`sqc-0.4.336-6fd686be`). Deliberately
excludes every finding attributable to the unrelated concurrent commit
`d0802e08` ("1099", proven-nonnull widening) — those are bmdb tasks 1106/1107's
scope, not this task's.

## Scope derivation

**EXP33-C**: `list_realworld_unlabeled(run=244, rule=EXP33-C)` returned only 15
unlabeled findings total (nearly the whole rule is already covered by prior
oracle labels at these codebases' pinned commits). 13 of the 15 are sqlite
`mptest/mptest.c`, `ext/fts3/fts3_test.c`, `ext/session/session_speed_test.c`,
`ext/session/test_session.c` — all explicitly out-of-scope per
`data/precision_audit/sqlite/README.md` (test harnesses / non-engine code).
The remaining 2 are both hostap, both in-scope.

**EXP34-C**: isolated 1099's effect first (separate measurement, bmdb 1106) by
diffing a pre-1099 baseline scan (`fd6d964a`) against run 244 per project,
restricted to EXP34-C. Intersection (present in both = NOT attributable to
1099) = 202 candidate findings across hostap/sqlite/pureftpd/curl/sel4 (0 for
mosquitto/lua/libcrc/raylib — no EXP34-C delta from this cluster there).
Applying each project's own in-scope predicate from its
`data/precision_audit/<project>/README.md` dropped sqlite entirely (all 25
candidates were `ext/*_test*.c`, `ext/expert/test_expert.c`,
`ext/rtree/test_rtreedoc.c`, `mptest/`, `src/tclsqlite.c`) and 14 of curl's 22
(`lib/vtls/schannel*.c`, Windows-only, excluded by the curl oracle's WIN_MAC
split). Net in-scope EXP34-C batch: **163 findings**.

| Project   | EXP34-C candidates | Dropped (out-of-scope)                          | In-scope |
|-----------|--------------------:|--------------------------------------------------|---------:|
| pureftpd  | 123                  | 0                                                  | 123      |
| hostap    | 30                   | 0                                                  | 30       |
| curl      | 22                   | 14 (`lib/vtls/schannel*.c`, Windows-only)          | 8        |
| sel4      | 2                    | 0                                                  | 2        |
| sqlite    | 25                   | 25 (test harnesses / bindings, see above)          | 0        |
| **Total** | **202**              | **39**                                             | **163**  |

Combined batch (EXP33-C + EXP34-C, in-scope): **165 findings**, adjudicated
via 3 parallel subagents (pureftpd standalone at 123; hostap combined
EXP33-C+EXP34-C at 32; curl+sel4 combined at 10), each confirming its pinned
checkout SHA before reading and reading the full containing function (not
just the flagged line) for every finding.

## Outcome

| Project   | Findings | TP | FP  | Precision |
|-----------|---------:|---:|----:|----------:|
| pureftpd  | 123      | 0  | 123 | 0.0%      |
| hostap    | 32       | 1  | 31  | 3.1%      |
| curl      | 8        | 0  | 8   | 0.0%      |
| sel4      | 2        | 0  | 2   | 0.0%      |
| **Total** | **165**  | **1** | **164** | **0.6%** |

Imported to the shared oracle (`sqc_claude_adjudicator` role) as sources
`task773_delta_exp34_pureftpd`, `task773_delta_exp3334_hostap`,
`task773_delta_exp34_curl_sel4`; adjudicator `claude-sonnet-5`.

## The one TP: `wpa_supplicant/config_winreg.c:279` (EXP33-C)

`int val;` (declared line 204, no initializer) is populated only on success by
`wpa_config_read_reg_dword(hk, TEXT("pmf"), &val)` at line 278 — and unlike the
sibling `eapol_version`/`extended_key_id` reads in the same function, which
correctly gate on the return value, this call's return is discarded. If the
`"pmf"` registry value is absent, `config->pmf = val;` at line 279 copies
genuine indeterminate stack garbage. Real bug, not previously caught.

## A tracked-history correction: `src/utils/eloop_win.c:658` flips TP-lean → FP

Task 773's own history (from the original EXP33-C delta) flagged this as one
of "four added sites, all unmaskings" and tentatively recommended labeling it
TP via the normal process. Independent re-verification found it's actually
**FP**: `eloop` is a file-scope `static struct eloop_data` with no explicit
initializer, so C guarantees zero-initialization — `eloop.readers` is NULL
even before `eloop_init()` runs, and `os_free()` (→ `free()`) is a defined
no-op on NULL. Every real call site across the tree calls `eloop_init()`
exactly once before `eloop_destroy()`. This is the same "implicit static
zero-init read as uninitialized" class that produced the original FP at line
654 — worth flagging as a case where a prior session's tentative read should
not be taken as settled without independent code verification, which is
exactly what happened here.

## FP causes: five recurring analyzer gaps, worth following up

1. **`noreturn` helpers not credited** (pureftpd, several sites) —
   `die_mem()`/`abort()` (`__attribute__((noreturn))`) and local
   `no_mem()`/`oom()`-style wrappers calling `exit()` guard many
   `malloc`/`ALLOCA` checks; sqc's null-state tracking doesn't model
   noreturn on the failure branch of an if/else.
2. **libc output-parameter contracts not modeled** (pureftpd) —
   `strtoul`/`strtoull`'s `endptr` is always written by the C standard, but
   sqc's new output-param tracking (the 1025-1029 cluster) apparently only
   covers in-repo macros/functions, not libc.
3. **`MAP_FAILED` sentinel, not NULL** (pureftpd, `pure-ftpwho.c:863`) — a
   real guard exists, but checks against the wrong sentinel value for
   `mmap()`'s failure return.
4. **Capability type-tag checks not recognized as a null-equivalent guard**
   (sel4, `src/fastpath/fastpath.c:365`) — `isValidVTableRoot_fp()` diverges
   via a `NORETURN` `slowpath()` call before an invalid/absent capability's
   base pointer would be dereferenced; sqc's guard-recognition doesn't model
   a capability-validity check as ruling out NULL.
5. **Address-of-field accessor getters misread as nullable** (curl,
   `lib/vtls/openssl.c:4778,4801`) — `Curl_ssl_cf_get_primary_config`/
   `_get_config` unconditionally return `&cf->conn->ssl_config` etc.; taking
   the address of a struct field can never itself be NULL, but sqc's
   analysis doesn't special-case address-of-field return values.

None of these were filed as new tasks here — they're pattern notes for
whoever next works EXP34-C's real-world FP volume (see bmdb 1107, which
covers the disjoint 1099-attributable additions and will likely hit the same
families).

## Files

CSVs: `data/precision_audit/{pureftpd,hostap,curl,sel4}/import_delta_exp3334_task773.csv`
(pureftpd/curl/sel4 files are named `import_delta_exp34_task773.csv` — EXP34-C
only; hostap's carries both rules).
