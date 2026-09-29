/* An allocator alias that is a platform hook in one build and calloc in the
 * other. The leak is reported in either case, and named after calloc. */
#include <stdlib.h>

#if defined(PLATFORM_HOOKS)
#define take_zeroed HOOK_CALLOC
#else
#define take_zeroed calloc
#endif

void keep_nothing(void) {
    char *p = take_zeroed(1, 8);
    if (p == NULL) return;
}
