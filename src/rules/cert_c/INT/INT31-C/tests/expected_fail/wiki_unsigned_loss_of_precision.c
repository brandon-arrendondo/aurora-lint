/*
 * Rule: INT31-C
 * Source: wiki
 * Status: EXPECTED FAIL - Known limitation: ULONG_MAX provably does not fit an
 * unsigned char, but INT31-C has no value-based definite-truncation
 * channel ahead of its provenance gate (INT30-C and INT32-C both have
 * one), so a local initialised from a constant reads as bounded local
 * state. A genuine INT31-C violation.
 * Description: Loss of precision in narrowing conversion
 */

#include <limits.h>

void testcase_unsigned_narrowing_no_check(void) {
    unsigned long int u_a = ULONG_MAX;
    unsigned char uc = (unsigned char)u_a;  /* Violation: value truncated */
    /* ... */
    (void)uc;
}
