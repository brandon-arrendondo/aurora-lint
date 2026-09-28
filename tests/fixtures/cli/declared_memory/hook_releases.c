/* A platform hook the scan has no definition for: whether it frees is the
 * project's to declare. */
#include <stdlib.h>

void release_once(void) {
    char *p = malloc(8);
    if (p == NULL) return;
    platform_give_back(p);
}
