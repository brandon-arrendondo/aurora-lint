/*
 * MEM30-C when a same-named static helper in another file never returns.
 * This file's die() returns, so on the `e` path p is freed and then written
 * and freed again. a_exits.c's static die() exits, and must not answer for
 * this one.
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
