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
 * Reason: Multiplication in malloc without wrap check (real-world vulnerability pattern)
 */

#include <stdlib.h>
#include <stddef.h>

void alloc_buffer(size_t num_elements) {
    // Multiplication may wrap - insufficient allocation
    int *buffer = (int *)malloc(num_elements * sizeof(int));  // Line 11 - VIOLATION

    if (buffer) {
        // Use buffer...
        free(buffer);
    }
}

int main(void) {
    alloc_buffer(SIZE_MAX / 2);  // Will wrap
    return 0;
}
