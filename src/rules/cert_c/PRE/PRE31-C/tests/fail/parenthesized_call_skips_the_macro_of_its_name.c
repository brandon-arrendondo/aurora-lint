/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Expect: default=clean strict=violation pedantic=violation
 * Reason: the parentheses keep the macro extfn from expanding, so
 * `(extfn)(1)` calls the function extfn, which nothing in the scan
 * defines; the macro's `(0)` says nothing about it. An unproven call is
 * reported by the strict policy.
 */

#define TWICE(x) ((x) + (x))

int extfn(int v);
#define extfn(v) (0)

int twice_called(void) {
    return TWICE((extfn)(1));  // Expect: here
}
