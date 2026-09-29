/*
 * Rule: MEM31-C
 *
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * hand_off() keeps the block for later in one build and frees it at once in
 * the other. Either way the caller has given the block away, so no build
 * leaks it: a store and a free are both a release, and every definition
 * releases.
 */
#include <stdlib.h>

static void *pending;

#ifdef DEFERRED_RELEASE
void hand_off(void *p)
{
    pending = p;
}
#else
void hand_off(void *p)
{
    free(p);
}
#endif

void flush_pending(void)
{
    free(pending);
    pending = NULL;
}

void use_buffer(void)
{
    char *buf = malloc(64);
    if (buf == NULL)
        return;
    buf[0] = 'x';
    hand_off(buf);
}
