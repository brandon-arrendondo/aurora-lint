/*
 * Rule: INT31-C
 * Source: custom
 * Status: EXPECTED FAIL - Known limitation: the source value is compile-time known
 * (1000) and provably does not fit the destination, but INT31-C has no
 * value-based definite-truncation channel at all -- unlike INT30-C and
 * INT32-C, whose provenance gates are preceded by
 * const_eval::expression_overflows_{unsigned,signed}_vra -- so the
 * provenance gate suppresses it. A genuine INT31-C violation.
 * Description: Variable-to-variable implicit narrowing without bounds check
 */

#include <stdint.h>

void func(void) {
    uint16_t wide = 1000;
    uint8_t narrow = wide;  /* Violation: uint16_t → uint8_t */
    (void)narrow;
}
