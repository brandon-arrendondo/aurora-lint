/*
 * Rule: INT31-C
 * Source: custom
 * Status: DETECTED. Was expected_fail until the value-based channels gained
 * interval division/remainder, a compound-assignment arm, a
 * definitely-negative left shift, and -- for INT31-C -- a definite-truncation
 * channel of its own. The operands here are compile-time known and the
 * operation provably misbehaves, so it is reported whatever their provenance.
 */

#include <stdint.h>

void func(void) {
    uint16_t wide = 1000;
    uint8_t narrow = wide;  /* Violation: uint16_t → uint8_t */
    (void)narrow;
}
