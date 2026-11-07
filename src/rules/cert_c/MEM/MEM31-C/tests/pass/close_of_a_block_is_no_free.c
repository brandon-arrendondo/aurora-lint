/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should not trigger MEM31-C violation
 * Description: close frees no memory, so freeing a block after handing it to
 * close is its first release and no double free.
 */

#include <stdlib.h>

extern int close(void *p);

int closed_then_freed(void)
{
    char *p = malloc(8);
    close(p);
    free(p);
    return 0;
}

struct holder {
    char *a;
};

int field_closed_then_freed(void)
{
    struct holder l;
    l.a = malloc(8);
    close(l.a);
    free(l.a);
    return 0;
}
