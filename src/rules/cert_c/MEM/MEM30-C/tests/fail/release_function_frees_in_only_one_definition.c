/*
 * Rule: MEM30-C
 *
 * Status: FAIL - Should trigger MEM30-C violation
 *
 * Only the #else definition of release() frees its argument. A build
 * without POOLED_RELEASE links it, and there the caller reads the block
 * after release() freed it. One definition that frees is enough to accuse.
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

int use_buffer(void)
{
    char *buf = malloc(64);
    if (buf == NULL)
        return 0;
    buf[0] = 'x';
    release(buf);
    return buf[0];
}
