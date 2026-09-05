/*
 * Rule: INT30-C
 * Source: testcases
 * Status: EXPECTED FAIL - Known limitation: the operand here is a function
 * parameter (or a local with no traced taint source), and INT30-C's opt-in
 * provenance gate (has_risky_operand_provenance, backed by int_provenance)
 * treats that as bounded local state, so the unsigned wrap is not
 * reported. That gate is what removes the bounded-counter false positives
 * on real code; flagging every unconstrained parameter is the noise it
 * exists to avoid. Detecting this needs caller-side bounds reasoning, not
 * a louder gate. The fixture is a genuine INT30-C violation and stays as
 * tracked evidence of the trade.
 */

/*
 * Rule: INT30-C - Ensure that unsigned integer operations do not wrap
 * Status: EXPECTED FAIL
 * Reason: Multiplication wrap in aligned_alloc call
 */

#include <stdlib.h>

void allocate_aligned(size_t count) {
    // Multiplication may wrap
    size_t size = count * sizeof(long long);  // Line 10 - VIOLATION

    void *ptr = aligned_alloc(16, size);
    if (ptr) {
        free(ptr);
    }
}

int main(void) {
    allocate_aligned(SIZE_MAX / 4);  // Will wrap
    return 0;
}
