/*
 * Rule: INT31-C
 * Source: real-world FN pattern
 * Status: FAIL - Should trigger INT31-C violation
 * Description: Cast widens to uint16_t, then implicit assignment narrows to uint8_t
 */

#include <stdint.h>

void parse_tag(const uint8_t *buffer) {
    uint8_t tag = (uint16_t)(buffer[0] << 8);  /* Violation: uint16_t → uint8_t */
    (void)tag;
}
