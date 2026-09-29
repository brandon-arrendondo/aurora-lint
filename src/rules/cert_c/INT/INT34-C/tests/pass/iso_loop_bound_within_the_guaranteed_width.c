/*
 * Rule: INT34-C
 * Source: regression
 * Status: PASS - bounded by the width ISO C guarantees
 *
 * unsigned int is at least 16 bits wherever the code is built, so shifting it
 * by less than 16 is defined with no data model declared, and a uint32_t is
 * exactly 32 bits, so shifting it by less than 32 is too.
 */

#include <stdint.h>

unsigned int low_bits(unsigned int x) {
    unsigned int result = 0;
    for (int i = 0; i < 16; i++) {
        result |= (x >> i) & 1u;
    }
    return result;
}

uint32_t all_bits(uint32_t x) {
    uint32_t result = 0;
    for (int i = 0; i < 32; i++) {
        result |= (x >> i) & 1u;
    }
    return result;
}
