/*
 * Rule: INT31-C
 * Source: wiki
 * Status: EXPECTED FAIL - a narrowing shape neither the caller-based provenance
 * work nor the value-based definite-truncation channel reaches: the converted
 * value's range is not compile-time known here, and the operand is not a
 * parameter whose callers the gate can judge. Genuine violation; kept as
 * tracked evidence of the gap.
 */

#include <limits.h>

void func(signed int si) {
    /* Cast eliminates warning but allows negative values */
    unsigned int ui = (unsigned int)si;  /* Violation: no bounds check */

    /* ... */
    (void)ui;
}

void testcase_signed_to_unsigned_no_check(void) {
    func(INT_MIN);
}
