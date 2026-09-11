/*
 * Rule: INT34-C
 * Source: testcases
 * Status: FAIL - A shift amount in [32, 63] is undefined for a 32-bit operand
 *
 * The mirror of testcases_shift_amount_within_64bit_operand_width.c: the same
 * [33, 39] loop bound, applied to operands that are 32 bits wide, that the
 * rule cannot type at all, or whose width is the data model's choice. The
 * 32-bit bound is the floor, so an operand the rule cannot resolve keeps it
 * -- widening happens only on positive, platform-independent evidence
 * (task 1119).
 */
#include <stdint.h>

typedef unsigned long word_t;
typedef word_t vptr_t;

/* Declared uint32_t. */
uint32_t shift_uint32_by_loop_bound(uint32_t x) {
    uint32_t acc = 0;
    for (unsigned i = 33; i < 40; i++) {
        acc += x >> i;
    }
    return acc;
}

/* An unsuffixed or `U` literal is int / unsigned int. */
uint32_t shift_unsuffixed_literal(void) {
    uint32_t b = 0;
    for (unsigned i = 33; i < 40; i++) {
        b |= 1U << i;
    }
    return b;
}

/* Element of 32-bit storage. */
uint32_t shift_32bit_element(uint32_t arr[4]) {
    uint32_t acc = 0;
    for (unsigned i = 33; i < 40; i++) {
        acc += arr[1] >> i;
    }
    return acc;
}

/* A bare `long`, even through a typedef chain, is 32 bits on LLP64: the
 * width is a data-model choice, not a standard guarantee, so it is not
 * evidence. The same stance INT30-C takes for `unsigned long`. */
word_t shift_platform_width_long(vptr_t vptr) {
    word_t acc = 0;
    for (unsigned i = 33; i < 40; i++) {
        acc += vptr >> i;
    }
    return acc;
}

/* A typedef the scan cannot resolve keeps the 32-bit floor. */
unsigned_word_t_from_elsewhere shift_unknown_typedef(unsigned_word_t_from_elsewhere x) {
    unsigned_word_t_from_elsewhere acc = 0;
    for (unsigned i = 33; i < 40; i++) {
        acc += x >> i;
    }
    return acc;
}
