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
 * Reason: User input multiplication without wrap check
 */

#include <stdlib.h>

void allocate_user_buffer(unsigned int user_count) {
    // User-controlled multiplication - security risk
    size_t size = user_count * 1024;  // Line 10 - VIOLATION

    void *buffer = malloc(size);
    if (buffer) {
        free(buffer);
    }
}

int main(void) {
    // Simulate malicious user input
    allocate_user_buffer(UINT_MAX / 512);  // Will wrap
    return 0;
}
