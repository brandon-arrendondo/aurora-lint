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
 * Reason: Multiple additions without wrap check
 */

#include <stddef.h>

void calculate_offset(size_t base, size_t offset1, size_t offset2, size_t offset3) {
    // Multiple additions - any may wrap
    size_t total = base + offset1 + offset2 + offset3;  // Line 11 - VIOLATION

    // Use total for file seeking or memory access...
}

int main(void) {
    calculate_offset(SIZE_MAX / 2, SIZE_MAX / 4, SIZE_MAX / 4, 100);
    return 0;
}
