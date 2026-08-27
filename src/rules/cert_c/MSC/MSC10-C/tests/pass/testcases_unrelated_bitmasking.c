/*
 * Rule: MSC10-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MSC10-C violation
 * Description: Ordinary byte/bit-level code that is not a UTF-8 decoder --
 * a high-bit test, a protocol header parse, and an alignment round-down
 * using top-bits-set masks. None of it performs the lead-byte mask
 * cascade, so the rule's recognition gate must not fire here.
 */

#include <stddef.h>

int has_high_bit(unsigned char c) {
    return (c & 0x80) != 0;
}

unsigned char frame_opcode(unsigned char b) {
    return b & 0x0f;
}

int frame_is_final(unsigned char b) {
    return (b & 0x80) == 0x80;
}

size_t round_down_to_4(size_t n) {
    return n & ~(size_t)0x3;
}

unsigned char clear_low_nibble(unsigned char b) {
    return b & 0xf0;
}

unsigned char top_six_bits(unsigned char b) {
    return b & 0xfc;
}
