/*
 * Rule: MEM04-C
 * Source: synthetic
 * Status: FAIL - The zero check is in another function
 *
 * check() tests its own size. Nothing tests the size make() allocates.
 */

#include <stdlib.h>

int check(size_t size)
{
    if (size == 0)
        return -1;
    return 0;
}

void *make(size_t size)
{
    return malloc(size);
}
