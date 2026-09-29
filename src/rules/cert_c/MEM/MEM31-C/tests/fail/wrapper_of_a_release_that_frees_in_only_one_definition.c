/*
 * Rule: MEM31-C
 *
 * Status: FAIL - Should trigger MEM31-C violation
 *
 * release() has two definitions, one per #if arm, and only the #else one
 * frees its argument. drop_buffer() has one definition, which hands its
 * argument to release(). In a build with POOLED_RELEASE defined neither
 * frees, so the block leaks there: a wrapper releases in every build only
 * what its callee releases in every build, however deep the wrapping.
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

void drop_buffer(void *p)
{
    release(p);
}

void use_buffer(void)
{
    char *buf = malloc(64);
    if (buf == NULL)
        return;
    buf[0] = 'x';
    drop_buffer(buf);
}
