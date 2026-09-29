/*
 * Rule: MEM31-C
 *
 * Status: EXPECTED_FAIL - a known gap, not detected yet
 *
 * release() has two definitions, one per #if arm, and only the #else one
 * frees its argument. drop_buffer() has one definition, which hands its
 * argument to release(). In a build with POOLED_RELEASE defined neither
 * frees, so the block leaks there.
 *
 * A definition is credited through a forward from what SOME definition of
 * the callee does, so drop_buffer() reads as freeing. Asking every
 * definition of the callee instead is right here, but without knowing
 * which definitions link together it also reads a porting stub (an empty
 * free beside an allocator that returns NULL, in one file) as a build that
 * leaks, when that build never allocates. Detecting this waits on modelling
 * that a translation unit's external definitions link together.
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
