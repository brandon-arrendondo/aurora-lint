/*
 * Rule: EXP14-C
 * Source: regression
 * Status: PASS - on a declared LP64 target
 * Settings: data_model=lp64
 *
 * uint32_t is exactly as wide as a 32-bit int, so its complement is not
 * promoted. ISO C alone does not rule out a wider int, which is why this
 * needs the declaration.
 */

#include <stdint.h>

uint32_t invert(uint32_t value) {
    uint32_t result = ~value;
    return result;
}
