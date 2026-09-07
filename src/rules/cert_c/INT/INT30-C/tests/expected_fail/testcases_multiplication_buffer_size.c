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
 * Reason: Multiplication for buffer size calculation without wrap check
 */

#include <stddef.h>

void calculate_buffer_size(size_t num_rows, size_t num_cols) {
    // Multiplication may wrap
    size_t buffer_size = num_rows * num_cols;  // Line 11 - VIOLATION

    // Use buffer_size for allocation...
}

int main(void) {
    calculate_buffer_size(SIZE_MAX / 100, 200);  // Will wrap
    return 0;
}
