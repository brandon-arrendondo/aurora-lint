/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: a loop condition is evaluated once per iteration.
 */

#define SPIN_UNTIL(c) do { } while (!(c))

void a(int i) {
    SPIN_UNTIL(i++ > 10);  // VIOLATION
}
