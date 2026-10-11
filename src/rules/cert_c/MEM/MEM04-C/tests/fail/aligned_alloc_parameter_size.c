/*
 * Rule: MEM04-C
 * Source: synthetic
 * Status: FAIL - aligned_alloc with an unchecked size
 */

#include <stdlib.h>

void *make(size_t n)
{
    return aligned_alloc(16, n);
}
