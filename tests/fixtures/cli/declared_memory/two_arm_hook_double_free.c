/* One build frees through a platform hook; the other through a hook the
 * project says nothing about. The declared build is enough to accuse. */
#include <stdlib.h>

#if defined(PLATFORM_HOOKS)
#define give_back HOOK_FREE
#else
#define give_back other_hook
#endif

void release_twice(void) {
    char *p = malloc(8);
    if (p == NULL) return;
    give_back(p);
    give_back(p);
}
