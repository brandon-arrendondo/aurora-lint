#include <stdlib.h>

void release_twice(void) {
    char *p = malloc(8);
    if (p == NULL) return;
    platform_give_back(p);
    platform_give_back(p);
}
