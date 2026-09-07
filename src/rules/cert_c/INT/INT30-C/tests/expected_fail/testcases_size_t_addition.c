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
 * Reason: size_t addition without wrap check before allocation
 */

#include <stdlib.h>
#include <stddef.h>

void allocate_memory(size_t size1, size_t size2) {
    // Addition may wrap
    size_t total_size = size1 + size2;  // Line 11 - VIOLATION

    char *buffer = (char *)malloc(total_size);
    if (buffer) {
        free(buffer);
    }
}

int main(void) {
    allocate_memory(SIZE_MAX - 100, 200);  // Will wrap
    return 0;
}
