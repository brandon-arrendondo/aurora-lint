/*
 * MEM31-C: a file-scope table filled once and kept for the
 * life of the process; the filling function is not its owner. valkey's
 * exec_argv and sel4's kernel tables, reduced.
 *
 * tests/cli_integration.rs asserts no loop-array finding here. Not a pass/
 * fixture: the main walk still reports the element it tracks under its
 * spelling (`saved_argv[j]`), which is a separate question from the
 * loop-array check.
 */

#include <stdlib.h>
#include <string.h>

#define MAX_ARGS 16

static char *saved_argv[MAX_ARGS];

void save_arguments(int argc, char **argv)
{
    int j;

    for (j = 0; j < argc && j < MAX_ARGS; j++) {
        saved_argv[j] = strdup(argv[j]);
    }
}
