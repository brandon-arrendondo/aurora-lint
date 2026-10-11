/*
 * Rule: MEM04-C
 * Source: synthetic
 * Status: FAIL - The guard tests the parameter; realloc gets a new variable
 * of the same name
 */

#include <stdlib.h>

void *grow(void *p, size_t n)
{
    if (n == 0)
        return NULL;
    {
        size_t n = 0;
        return realloc(p, n);
    }
}
