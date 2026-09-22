/*
 * Rule: EXP34-C
 * Source: testcases (mosquitto log__printf cohort)
 * Status: FAIL - `relay` reaches `record` on the branch where the `!text`
 *         disjunct may be what made the condition true, so a null pointer
 *         flows into a callee that dereferences it without checking.
 *
 * The call-site check used to fire only on a DefinitelyNull argument, which
 * left it asymmetric with the libc-allowlist path (that reports a merely
 * possibly-null one) and blind to every maybe-null flow into a project
 * function. mosquitto's log__printf is the motivating case: a project
 * logging wrapper takes its argument through `...`, so no position-indexed
 * summary can model it and only the call-site check can see it at all.
 *
 * `relay`'s parameter is ASSUMED non-null (no caller evidence), not PROVEN
 * non-null, so the `!text` disjunct stands and the join to PossiblyNull is
 * correct here -- the contrast with the proven-nonnull pass fixture.
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
