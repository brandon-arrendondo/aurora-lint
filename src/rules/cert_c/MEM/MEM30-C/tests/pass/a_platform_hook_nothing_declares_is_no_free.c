/*
 * Rule: MEM30-C - Do not access freed memory
 * Status: PASS
 * Reason: platform_give_back is a hook the scan has no definition for, and
 *         nothing declares it a deallocator. Without that proof the call does
 *         not free p, so the write after it is not a use after free.
 */

#include <stdlib.h>

void use_after_hook(void) {
    char *p = malloc(8);
    if (p == NULL) return;
    platform_give_back(p);
    p[0] = 1;
    free(p);
}
