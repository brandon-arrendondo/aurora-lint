/*
 * Rule: MEM31-C
 *
 * Status: FAIL - Should trigger MEM31-C violation
 *
 * release() frees its argument in the #else definition only. In that build
 * the free() after it releases the block a second time. A release some
 * definition makes is enough to accuse a later free; it takes every
 * definition to forgive a leak.
 */
#include <stdlib.h>

#ifdef POOLED_RELEASE
void release(void *p)
{
    (void)p;
}
#else
void release(void *p)
{
    free(p);
}
#endif

void use_buffer(void)
{
    char *buf = malloc(64);
    if (buf == NULL)
        return;
    buf[0] = 'x';
    release(buf);
    free(buf);
}
