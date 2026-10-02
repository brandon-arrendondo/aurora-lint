/*
 * Rule: INT02-C
 * Source: regression
 * Status: PASS - no data model is declared
 *
 * The product of two signed narrow operands is computed in int and may
 * overflow it where int is only 16 bits, but that is a signed overflow,
 * reported by INT32-C on the same line. This rule's multiplication is the
 * unsigned one: two unsigned operands promoting to a signed int.
 */

#include <stdint.h>

int short_product(short a, short b) {
    return a * b;
}

int fixed_width_product(int16_t a, int16_t b) {
    return a * b;
}

int char_product(signed char a, signed char b) {
    return a * b;
}
