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
 * Reason: Wrapped addition for buffer copy size
 */

#include <string.h>
#include <stddef.h>

void copy_buffers(char *dest, const char *src, size_t size1, size_t size2) {
    // Addition may wrap
    size_t total_size = size1 + size2;  // Line 11 - VIOLATION

    memcpy(dest, src, total_size);
}

int main(void) {
    char dest[100], src[100];
    copy_buffers(dest, src, SIZE_MAX - 50, 100);  // Will wrap
    return 0;
}
