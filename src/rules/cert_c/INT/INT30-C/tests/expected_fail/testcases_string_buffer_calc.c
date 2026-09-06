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
 * Reason: Addition for string buffer size without wrap check
 */

#include <stdlib.h>
#include <string.h>

void concatenate_strings(const char *str1, const char *str2) {
    size_t len1 = strlen(str1);
    size_t len2 = strlen(str2);

    // Addition may wrap
    size_t total_len = len1 + len2 + 1;  // Line 14 - VIOLATION

    char *result = malloc(total_len);
    if (result) {
        free(result);
    }
}

int main(void) {
    char large[SIZE_MAX / 2];
    concatenate_strings(large, large);
    return 0;
}
