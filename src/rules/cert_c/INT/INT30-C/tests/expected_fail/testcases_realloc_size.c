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
