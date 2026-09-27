/*
 * MEM30-C through a static noreturn helper from a .c file this one
 * #includes. die() in helpers.c exits, so on the `e` path nothing runs after
 * free(p): no use after free, no double free.
 */
#include <stdio.h>
#include <stdlib.h>
#include "helpers.c"

int no_use_after_free_when_die_exits(int e) {
    char *p = malloc(10);
    if (p == NULL)
        return -1;
    if (e) {
        free(p);
        die();
    }
    p[0] = 'x';
    free(p);
    return 0;
}
