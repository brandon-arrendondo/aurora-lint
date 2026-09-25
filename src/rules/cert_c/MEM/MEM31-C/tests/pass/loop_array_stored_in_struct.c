/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - the loop stores its elements into an object reached through
 *         a pointer; that object's own release routine frees them.
 *
 * valkey's client argv and hostap's per-interface bss array, reduced
 * (aurora_lint 1494). The function filling the array is not its owner.
 */

#include <stdlib.h>

struct client {
    int argc;
    char **argv;
};

void fill_argv(struct client *c, int argc)
{
    int j;

    c->argc = argc;
    for (j = 0; j < argc; j++) {
        c->argv[j] = malloc(32);
    }
}

void free_client_argv(struct client *c)
{
    int j;

    for (j = 0; j < c->argc; j++)
        free(c->argv[j]);
}
