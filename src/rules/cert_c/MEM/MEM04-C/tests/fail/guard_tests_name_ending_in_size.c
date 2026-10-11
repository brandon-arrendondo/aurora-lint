/*
 * Rule: MEM04-C
 * Source: synthetic
 * Status: FAIL - The guard tests n_size, not size
 *
 * `n_size == 0` contains the text `size == 0`, but says nothing about size.
 */

#include <stdlib.h>

void *make(size_t size, size_t n_size)
{
    if (n_size == 0)
        return NULL;
    return malloc(size);
}
