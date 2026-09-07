/*
 * Rule: INT30-C
 * Source: testcases
 * Status: EXPECTED FAIL, by measurement rather than oversight. The operand is a
 * parameter, and the provenance gate now does reason about parameters via the
 * call graph -- but it judges this one BOUNDED, because the only caller in the
 * scan set is a taint-free `main`. That approximation is the gate's limit: the
 * prescan summaries carry per-function taint, not per-argument value ranges, so
 * `main` handing this function INT_MAX or SIZE_MAX/2 is unbounded in value yet
 * carries no taint. Detecting it needs per-call-site argument ranges joined
 * across callers into a summary field -- a distinct piece of work, and NOT a
 * reason to loosen the gate, which would restore the parameter false positives
 * the caller-set rule exists to avoid. Genuine violation; kept as evidence.
 */

/*
 * Rule: INT30-C - Ensure that unsigned integer operations do not wrap
 * Status: EXPECTED FAIL
 * Reason: Addition in loop condition without bounds check
 */

#include <limits.h>

void increment_no_check(unsigned int start) {
    unsigned int i;

    // Loop with unchecked unsigned addition in condition
    for (i = start; i < start + 100; i++) {
        // Process...
    }
}

int main(void) {
    increment_no_check(UINT_MAX - 50);
    return 0;
}
