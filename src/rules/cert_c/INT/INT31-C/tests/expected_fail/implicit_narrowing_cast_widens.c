/*
 * Rule: INT31-C
 * Source: real-world FN pattern
 * Status: EXPECTED FAIL - a narrowing shape neither the caller-based provenance
 * work nor the value-based definite-truncation channel reaches: the converted
 * value's range is not compile-time known here, and the operand is not a
 * parameter whose callers the gate can judge. Genuine violation; kept as
 * tracked evidence of the gap.
 */

#include <stdint.h>

void parse_tag(const uint8_t *buffer) {
    uint8_t tag = (uint16_t)(buffer[0] << 8);  /* Violation: uint16_t → uint8_t */
    (void)tag;
}
