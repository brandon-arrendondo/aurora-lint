/*
 * Rule: INT30-C
 * Source: regression
 * Status: PASS - no data model is declared
 *
 * ISO C does not fix the size of an exact-width type: uint32_t is four bytes
 * only where char is eight bits, and is never fewer than one. A macro written
 * over those sizes is therefore bounded, not unknown: HEADER_SIZE is at least
 * three bytes, so a length that passed `length < HEADER_SIZE` is at least
 * three and `length - 3` cannot wrap. The same guard written inline already
 * counted; the macro made it vanish.
 */

typedef unsigned long size_t;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

#define HEADER_SIZE (sizeof(uint32_t) * 2 + sizeof(uint16_t))
#define TRAILER_SIZE (sizeof(uint8_t))

size_t payload(size_t length) {
    if (length < HEADER_SIZE + TRAILER_SIZE) {
        return 0;
    }
    return length - TRAILER_SIZE;
}

size_t after_header(size_t length) {
    if (length < HEADER_SIZE) {
        return 0;
    }
    return length - 3;
}
