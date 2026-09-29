/* A wrapper that frees through an alias which is a platform hook in one
 * build and free in the other (mbedtls's mbedtls_zeroize_and_free calling
 * mbedtls_free). Once the hook is declared, the wrapper frees its argument
 * in every build, so what a caller hands it is released. */
#include <stdlib.h>

#if defined(PLATFORM_HOOKS)
#define give_back HOOK_FREE
#else
#define give_back free
#endif

void wipe_and_give_back(void *buf)
{
    give_back(buf);
}

void release_through_wrapper(void)
{
    char *p = malloc(8);
    if (p == NULL) return;
    wipe_and_give_back(p);
}
