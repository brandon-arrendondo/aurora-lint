/*
 * Rule: MEM04-C
 * Source: synthetic
 * Status: FAIL - The macro's size reads its count parameter inside a product
 */

#include <stdlib.h>

#define ALLOC_N(T, n) malloc(sizeof(T) * (n))

int *numbers(size_t n)
{
    return ALLOC_N(int, n);
}
