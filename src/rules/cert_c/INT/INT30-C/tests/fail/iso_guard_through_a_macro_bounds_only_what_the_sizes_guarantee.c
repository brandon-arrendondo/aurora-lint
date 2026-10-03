/*
 * Rule: INT30-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * HEADER_SIZE is between three and ten bytes under ISO C's widths, so a
 * length that passed `length < HEADER_SIZE` is only known to be at least
 * three. Subtracting five can wrap for a length of three or four on a target
 * where every one of those types is a single byte. On a declared target the
 * header is ten bytes and the subtraction is safe (tests/pass).
 */

typedef unsigned long size_t;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

#define HEADER_SIZE (sizeof(uint32_t) * 2 + sizeof(uint16_t))

size_t after_header(size_t length) {
    if (length < HEADER_SIZE) {
        return 0;
    }
    return length - 5; /* VIOLATION */
}
