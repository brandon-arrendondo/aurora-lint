/*
 * Rule: EXP34-C
 * Source: testcases (mosquitto log__printf cohort)
 * Status: EXPECTED_FAIL - Known limitation, tracked by an earlier fix.
 *         `relay` reaches `record` on the branch where the `!text` disjunct
 *         may be what made the condition true, so a null pointer flows into
 *         a callee that dereferences it without checking.
 *
 * HISTORICAL (why the call-site check existed before an earlier fix): it used to
 * fire only on a DefinitelyNull argument, which left it asymmetric with the
 * libc-allowlist path (that reports a merely possibly-null one) and blind to
 * every maybe-null flow into a project function. `relay`'s parameter is
 * ASSUMED non-null (no caller evidence), not PROVEN non-null, so the `!text`
 * disjunct stands and the join to PossiblyNull is correct here -- the
 * contrast with the proven-nonnull pass fixture.
 *
 * REGRESSED by an earlier fix: `record` takes one ordinary positional parameter,
 * not `...` (unlike the vararg carve-out an earlier fix kept the call-site check
 * for), so EXP34-C now relies entirely on `record`'s own callee-side seed
 * from prescan's `callsite_param_null_states`. Prescan's `infer_call_arg_state`/
 * `guarded_nonnull_in` are flow-insensitive and dominator-based, not a real
 * CFG join, so they cannot see that reaching `record(text)` through the
 * unprovable `!text` disjunct means `text` may still be null here -- they
 * classify it `Unknown` (abstains from the vote) where the full per-function
 * CFG dataflow the old call-site check used correctly computed `PossiblyNull`.
 * Fix belongs to 1427 (teach prescan's disjunctive-guard reasoning to match),
 * not here.
 */

#include <string.h>

static void record(const char *s)
{
    /* Dereferences without a null check: the callee makes no promise. */
    char first = *s;
    (void)first;
}

int relay(const char *text)
{
    if (!text || strlen(text) != 0) {
        record(text);
        return 1;
    }
    return 0;
}
