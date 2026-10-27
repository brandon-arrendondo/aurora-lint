/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Expect: default=clean strict=violation pedantic=violation
 * Reason: `(hook)(v)` calls through a function pointer, which may change
 * anything; twice evaluates its argument twice. Only the strict policy
 * reports an unproven call.
 */

#define twice(x) ((x) + (x))

int (*hook)(int);

int g(int v) {
    return twice((hook)(v));  // Expect: here
}
