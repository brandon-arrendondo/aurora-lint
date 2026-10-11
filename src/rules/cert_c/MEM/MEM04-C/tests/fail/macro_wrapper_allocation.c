/*
 * Rule: MEM04-C
 * Source: synthetic
 * Status: FAIL - The macro passes its argument to malloc as the size
 */

#include <stdlib.h>

#define XMALLOC(n) malloc(n)

void *make(size_t n)
{
    return XMALLOC(n);
}
