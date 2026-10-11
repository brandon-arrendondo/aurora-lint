/*
 * Rule: MEM04-C
 * Source: synthetic
 * Status: FAIL - n is non-zero, but n * sizeof(struct item) may wrap to zero
 */

#include <stdlib.h>

struct item {
    int key;
    int value;
};

struct item *items(size_t n)
{
    if (n == 0)
        return NULL;
    return malloc(n * sizeof(struct item));
}
