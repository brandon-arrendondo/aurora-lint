/*
 * Rule: MEM31-C
 * Source: real-world (hostap src/ap/acs.c, src/utils/eloop_win.c:
 *         `os_free(d.handles)`, `os_free(paths[i])`)
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: `release` frees its argument by its body. Handed a field or
 * an array element by value, it releases that block as surely as a plain
 * variable, so neither allocation leaks.
 */
#include <stdlib.h>

struct dispatch {
    char *handles;
};

void release(void *p)
{
    free(p);
}

void field_argument(void)
{
    struct dispatch d;

    d.handles = malloc(8);
    if (d.handles == NULL) {
        return;
    }
    release(d.handles);
}

void element_argument(void)
{
    char *paths[4];
    int i;

    for (i = 0; i < 4; i++) {
        paths[i] = malloc(8);
    }
    for (i = 0; i < 4; i++) {
        release(paths[i]);
    }
}
