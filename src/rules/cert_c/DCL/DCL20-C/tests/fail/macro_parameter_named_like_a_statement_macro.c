/*
 * Rule: DCL20-C
 * Source: aurora-lint
 * Status: FAIL - the replacement list begins with a parameter, not with the
 *         statement macro of the same name
 * Expect: count=1
 *
 * APPLY's `CHECK` is its parameter, replaced by the argument `AS_TYPE`, so
 * `APPLY(AS_TYPE) compute();` expands to `int compute();`.
 */

#define CHECK(x) if (x)
#define AS_TYPE(t) int
#define APPLY(CHECK) CHECK(int)

APPLY(AS_TYPE) compute(); /* Expect: here */
