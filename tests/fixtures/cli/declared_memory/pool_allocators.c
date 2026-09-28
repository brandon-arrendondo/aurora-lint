#include <stdlib.h>

extern void *pool_take(size_t n);
extern void *pool_grow(void *old, size_t n);

void taken_and_dropped(void) {
    char *p = pool_take(8);
    if (p == NULL) return;
    p[0] = 1;
}

void grown_then_old_used(void) {
    char *p = malloc(8);
    if (p == NULL) return;
    char *q = pool_grow(p, 16);
    if (q == NULL) { free(p); return; }
    p[0] = 1;
    free(q);
}
