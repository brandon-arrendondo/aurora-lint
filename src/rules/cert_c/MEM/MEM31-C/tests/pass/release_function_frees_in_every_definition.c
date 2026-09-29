/*
 * Rule: MEM31-C
 *
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * release() has two definitions, one per #if arm, and both free their
 * argument, so the call releases the block in every build.
 */
#include <stdlib.h>

#ifdef TRACED_RELEASE
void release(void *p)
{
    if (p == NULL)
        return;
    free(p);
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
