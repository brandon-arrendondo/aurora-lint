/*
 * MEM31-C, aurora_lint 1494: the array whose elements the loop allocates is
 * returned, so its caller owns them and frees them with its own loop.
 * hostap's command-completion builders, reduced.
 *
 * tests/cli_integration.rs asserts no loop-array finding here. Not a pass/
 * fixture: the main walk still reports the element it tracks under its
 * spelling (`res[i]`), which is a separate question from the loop-array check.
 */

#include <stdlib.h>
#include <string.h>

char **build_list(const char *const *names, int count)
{
    char **res;
    int i;

    res = calloc(count + 1, sizeof(char *));
    if (res == NULL)
        return NULL;
    for (i = 0; i < count; i++) {
        res[i] = strdup(names[i]);
    }
    return res;
}

void free_list(char **list)
{
    int i;

    if (list == NULL)
        return;
    for (i = 0; list[i]; i++)
        free(list[i]);
    free(list);
}
