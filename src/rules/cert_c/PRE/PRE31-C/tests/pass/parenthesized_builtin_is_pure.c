/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Expect: default=clean strict=clean
 * Reason: `(__builtin_expect)(v, 1)` is the builtin in parentheses, which
 * changes nothing, as it does unparenthesized.
 */

#define TWICE(x) ((x) + (x))

long likely(long v) {
    return TWICE((__builtin_expect)(v, 1));
}
