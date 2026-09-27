/*
 * MEM30-C when another file's external function of the same name never
 * returns. This file's static die() returns, so on the `e` path p is freed
 * and then written and freed again. a_exits.c's external die() exits, but
 * a call here reaches this file's own static.
 */
#include <stdio.h>
#include <stdlib.h>

static void die(void) { fputs("note\n", stderr); }

int use_after_free_when_die_returns(int e) {
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
