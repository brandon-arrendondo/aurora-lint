/* An alias that is a platform hook in one build and free in the other. It
 * frees in every build only once the project says what the hook does. */
#include <stdlib.h>

#if defined(PLATFORM_HOOKS)
#define give_back HOOK_FREE
#else
#define give_back free
#endif

void release_through_alias(void) {
    char *p = malloc(8);
    if (p == NULL) return;
    give_back(p);
}
