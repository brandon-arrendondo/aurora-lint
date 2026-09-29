/*
 * Rule: INT34-C
 * Source: testcases
 * Status: PASS - Various validated shift patterns
 * Settings: data_model=lp64
 *
 * The bounds are 32 because the target is declared LP64, where unsigned
 * int is 32 bits; ISO C guarantees it only 16.
 */

#include <limits.h>

/* Shift by literal — compiler handles this */
unsigned int shift_by_literal(unsigned int x) {
    return x << 5;
}

/* Shift by zero literal */
unsigned int shift_by_zero(unsigned int x) {
    return x << 0;
}

/* Validated with if-return pattern */
unsigned int validated_with_return(unsigned int x, unsigned int amount) {
    if (amount >= 32) {
        return 0;
    }
    return x << amount;
}

/* Validated with negative check for signed */
long validated_signed_shift(long x, int amount) {
    if (amount < 0 || amount >= (int)(sizeof(long) * CHAR_BIT)) {
        return 0;
    }
    return x << amount;
}

/* Validated via loop bounds */
unsigned int shift_in_bounded_loop(unsigned int x) {
    unsigned int result = 0;
    for (int i = 0; i < 32; i++) {
        result |= (x << i);
    }
    return result;
}

/* Right-shift by literal */
unsigned int right_shift_literal(unsigned int x) {
    return x >> 8;
}
