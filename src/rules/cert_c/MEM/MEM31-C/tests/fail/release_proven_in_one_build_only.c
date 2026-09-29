/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: In builds with PLATFORM_HOOKS, `my_release` is the platform's
 * `hook_release`, whose body is not in the scan; in the others it is the
 * function below, which frees. The free is proven in one build only, and a
 * leak is withheld only on what every build agrees on (ADR-0010), so the
 * block is reported leaked.
 */
#include <stdlib.h>

#ifdef PLATFORM_HOOKS
#define my_release hook_release
void hook_release(void *p);
#else
void my_release(void *p)
{
    free(p);
}
#endif

void use(void)
{
    /* VIOLATION: not freed in the PLATFORM_HOOKS build */
    char *p = malloc(8);
    if (p == NULL) {
        return;
    }
    my_release(p);
}
