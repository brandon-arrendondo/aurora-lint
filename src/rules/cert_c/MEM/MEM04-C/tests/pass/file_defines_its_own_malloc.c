/*
 * Rule: MEM04-C
 * Source: synthetic
 * Status: PASS - malloc here is the file's own function
 *
 * The file defines malloc, so a call to it reaches this definition, not
 * the library's allocator.
 */

#include <stddef.h>

static char pool[4096];
static size_t used;

void *malloc(size_t n)
{
    void *p = &pool[used];
    used += n;
    return p;
}

void *make(size_t n)
{
    return malloc(n);
}
