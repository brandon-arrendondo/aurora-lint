/*
 * Rule: MEM04-C
 * Source: synthetic
 * Status: FAIL - The size is read from input and not checked for zero
 */

#include <stdio.h>
#include <stdlib.h>

void *make(void)
{
    int n;
    if (scanf("%d", &n) != 1)
        return NULL;
    return malloc(n);
}
