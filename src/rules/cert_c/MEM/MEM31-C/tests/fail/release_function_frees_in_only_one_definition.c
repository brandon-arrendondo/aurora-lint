/*
 * Rule: MEM31-C
 *
 * Status: FAIL - Should trigger MEM31-C violation
 *
 * release() has two definitions, one per #if arm, and only the #else one
 * frees its argument. The caller compiles under both arms, so a build with
 * POOLED_RELEASE defined links the definition that keeps the block, and the
 * allocation leaks there. A leak is forgiven only when every definition the
 * call can link with releases the block.
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
}
