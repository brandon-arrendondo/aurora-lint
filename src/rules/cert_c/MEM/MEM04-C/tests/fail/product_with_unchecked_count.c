/*
 * Rule: MEM04-C
 * Source: synthetic
 * Status: FAIL - n * sizeof(int) is zero when n is
 *
 * sizeof(int) is never zero, but the product is zero whenever the count
 * the caller passed is.
 */

#include <stdlib.h>

int *make(size_t n)
{
    return malloc(n * sizeof(int));
}
