/*
 * MEM31-C, aurora_lint 1494: every element is released on the way out, by a
 * `while` unwind loop through a project deallocator rather than a `for` loop
 * calling free(). hostap's D-Bus object-path arrays, reduced: the pairing
 * only recognised `free(a[i])` in a `for`, so `os_free(paths[--i])` at the
 * `out:` label counted for nothing.
 *
 * tests/cli_integration.rs asserts no loop-array finding here. Not a pass/
 * fixture: the main walk still reports the element it tracks under its
 * spelling (`paths[i]`), which `os_free(paths[--i])` does not match -- a
 * separate question from the loop-array check.
 */

#include <stdlib.h>

static void os_free(void *p)
{
    free(p);
}

int send_paths(int num)
{
    char **paths;
    int i = 0;
    int ret = -1;

    paths = calloc(num, sizeof(char *));
    if (paths == NULL)
        return -1;
    for (i = 0; i < num; i++) {
        paths[i] = malloc(64);
        if (paths[i] == NULL)
            goto out;
    }
    ret = 0;
out:
    while (i)
        os_free(paths[--i]);
    os_free(paths);
    return ret;
}
