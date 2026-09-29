/*
 * Rule: EXP14-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * uint32_t is exactly 32 bits, and ISO C lets int be wider (ILP64 targets
 * have a 64-bit int). There the operand promotes to int before the
 * complement, whose upper bits are then all set. On a declared LP64 target,
 * where int is 32 bits, the same code is not promoted
 * (tests/pass/lp64_int_wide_operand.c).
 */

#include <stdint.h>

uint32_t invert(uint32_t value) {
    uint32_t result = ~value; /* VIOLATION */
    return result;
}
