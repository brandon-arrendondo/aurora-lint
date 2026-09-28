/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: FAIL
 * Reason: platform_give_back is a hook the scan has no definition for, and
 *         nothing declares it a deallocator ([environment.deallocators] or
 *         --deallocator). Its name proves nothing, so the block is never
 *         shown to be freed and leaks.
 */

#include <stdlib.h>

void release_once(void) {
    char *p = malloc(8);
    if (p == NULL) return;
    platform_give_back(p);
}
