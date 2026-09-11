/*
 * Rule: INT34-C
 * Source: testcases
 * Status: PASS - A shift amount in [32, 63] is defined for a 64-bit operand
 *
 * C11 6.5.7p3 makes the hazard relative to the width of the LEFT operand.
 * Every shift here is bounded to [33, 39] by its loop and applied to an
 * operand the rule can resolve to 64 bits -- directly, through a typedef
 * chain, a cast, a literal suffix, a dereference or an array element.
 * The rule once compared every amount against a fixed 32 and reported all
 * of these as if the operand were uint32_t (task 1119).
 */
#include <stdint.h>

typedef unsigned long word_t;
typedef word_t vptr_t;

/* Declared uint64_t. */
uint64_t shift_uint64_by_loop_bound(uint64_t x) {
    uint64_t acc = 0;
    for (unsigned i = 33; i < 40; i++) {
        acc += x >> i;
    }
    return acc;
}

/* Two-level typedef chain to unsigned long. */
word_t shift_typedef_chain_by_loop_bound(vptr_t vptr) {
    word_t acc = 0;
    for (unsigned i = 33; i < 40; i++) {
        acc += vptr >> i;
    }
    return acc;
}

/* A cast fixes the operand's type, whatever the inner expression was. */
uint64_t shift_cast_widened_operand(uint32_t x) {
    uint64_t acc = 0;
    for (unsigned i = 33; i < 40; i++) {
        acc += (uint64_t)x << i;
    }
    return acc;
}

/* A `ULL` suffix fixes the literal's type. */
uint64_t shift_suffixed_literal(void) {
    uint64_t a = 0;
    for (unsigned i = 33; i < 40; i++) {
        a |= 1ULL << i;
    }
    return a;
}

/* Dereference and element of 64-bit storage. */
uint64_t shift_pointee_and_element(uint64_t *p, uint64_t arr[4]) {
    uint64_t acc = 0;
    for (unsigned i = 33; i < 40; i++) {
        acc += *p >> i;
        acc += arr[1] >> i;
    }
    return acc;
}

/* A local whose declared type is unsigned long long, qualified. */
unsigned long long shift_qualified_local(unsigned long long seed) {
    const unsigned long long base = seed;
    unsigned long long acc = 0;
    for (unsigned i = 40; i < 63; i++) {
        acc ^= base << i;
    }
    return acc;
}
