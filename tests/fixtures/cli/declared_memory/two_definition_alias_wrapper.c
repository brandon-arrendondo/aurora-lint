/* A wrapper with two definitions, each freeing through an alias that is a
 * platform hook in one build and free in the other. A leak is excused only
 * when every definition of the wrapper releases, so each definition's own
 * forward must be read through the same alias the frees fixpoint used:
 * once the hook is declared, both definitions free in every build. */
#include <stdlib.h>
#include <string.h>

#if defined(PLATFORM_HOOKS)
#define give_back HOOK_FREE
#else
#define give_back free
#endif

#if defined(ZEROIZE)
void wipe_and_give_back(void *buf)
{
    memset(buf, 0, 8);
    give_back(buf);
}
#else
void wipe_and_give_back(void *buf)
{
    give_back(buf);
}
#endif

void release_through_wrapper(void)
{
    char *p = malloc(8);
    if (p == NULL) return;
    wipe_and_give_back(p);
}
