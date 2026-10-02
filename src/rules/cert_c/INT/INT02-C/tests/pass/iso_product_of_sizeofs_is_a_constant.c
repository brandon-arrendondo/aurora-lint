/*
 * Rule: INT02-C
 * Source: regression
 * Status: PASS - no data model is declared
 *
 * size_t may rank below int where int is wider than it, so a product of two
 * size_t values can be computed in a signed int. A product of sizeofs is a
 * constant whose factors are each a type's width in bytes, far below what
 * could overflow an int on any implementation, so it is not reported.
 */

#include <stddef.h>

size_t pair_size(void) {
    return sizeof(int) * sizeof(long);
}
