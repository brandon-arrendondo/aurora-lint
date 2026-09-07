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
 * Reason: Wrapped multiplication used with realloc
 */

#include <stdlib.h>
#include <stddef.h>

void grow_buffer(void *old_ptr, size_t old_count, size_t growth) {
    // Addition may wrap
    size_t new_count = old_count + growth;  // Line 11 - VIOLATION

    // Multiplication may wrap
    void *new_ptr = realloc(old_ptr, new_count * sizeof(int));  // Line 14 - VIOLATION

    if (new_ptr) {
        free(new_ptr);
    }
}

int main(void) {
    int *ptr = malloc(100 * sizeof(int));
    if (ptr) {
        grow_buffer(ptr, SIZE_MAX / 8, SIZE_MAX / 2);
    }
    return 0;
}
