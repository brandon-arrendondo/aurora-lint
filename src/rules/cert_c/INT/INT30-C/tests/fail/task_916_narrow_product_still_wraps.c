/*
 * Rule: INT30-C
 * Source: task 916
 * Status: FAIL - a product of two unsigned ints wraps in 32 bits
 *
 * The counterpart to task_916_width_bounded_size_t_product.c: here the
 * arithmetic itself is 32-bit, so widening to the size_t destination would be
 * wrong -- the wrap happens during the multiply, before the store widens
 * anything.
 */

#include <stdlib.h>

size_t scale(const char *a, const char *b) {
    unsigned int x = (unsigned int)atoi(a);
    unsigned int y = (unsigned int)atoi(b);
    size_t total = x * y;
    return total;
}
