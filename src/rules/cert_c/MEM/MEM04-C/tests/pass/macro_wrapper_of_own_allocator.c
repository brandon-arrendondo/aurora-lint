/*
 * Rule: MEM04-C
 * Source: synthetic
 * Status: PASS - The macro wraps the file's own malloc, not the library's
 */

#include <stddef.h>

static char pool[4096];
static size_t used;

void *malloc(size_t n)
{
    void *p = pool + used;
    used += n;
    return p;
}

#define xmalloc(n) malloc(n)

void *take(size_t n)
{
    return xmalloc(n);
}
