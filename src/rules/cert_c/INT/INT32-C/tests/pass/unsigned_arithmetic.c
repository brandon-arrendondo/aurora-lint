/*
 * Rule: INT32-C
 * Source: real-world FP pattern
 * Status: PASS - Unsigned arithmetic should not trigger INT32-C
 *
 * INT32-C applies to signed integer overflow only.  Unsigned wrap-around
 * is well-defined in C and is covered by INT30-C instead.
 */

#include <stdint.h>

uint16_t increment_index(uint16_t index) {
    uint16_t nextIndex = index + 1;    /* unsigned + literal: INT30-C, not INT32-C */
    return nextIndex;
}

uint32_t unsigned_add(uint32_t a, uint32_t b) {
    return a + b;    /* both unsigned */
}

uint32_t unsigned_mul(uint32_t a, uint32_t b) {
    return a * b;    /* both unsigned */
}

uint16_t unsigned_sub(uint16_t a, uint16_t b) {
    return a - b;    /* both unsigned */
}

unsigned int unsigned_div(unsigned int a, unsigned int b) {
    return a / b;    /* both unsigned */
}

unsigned int unsigned_mod(unsigned int a, unsigned int b) {
    return a % b;    /* both unsigned */
}
