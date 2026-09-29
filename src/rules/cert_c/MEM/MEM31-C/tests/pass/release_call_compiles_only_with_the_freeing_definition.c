/*
 * Rule: MEM31-C
 *
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * Only the #else definition of release() frees its argument, but the call
 * sits in the same #else arm: it can only ever link with the definition
 * that frees, so the block is released in every build that compiles it.
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

void use_buffer(void)
{
    char *buf = malloc(64);
    if (buf == NULL)
        return;
    buf[0] = 'x';
    release(buf);
}
#endif
