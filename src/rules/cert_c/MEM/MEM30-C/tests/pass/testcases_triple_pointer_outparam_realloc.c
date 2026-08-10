/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM30-C violation
 */

/*
 * Rule: MEM30-C - Do not access freed memory
 * Status: PASS
 * Reason: `if_names` is a triple-pointer out-param (`char ***`). The
 * function reallocs the *pointee* `*if_names` (the buffer the caller's
 * `char **` variable points to), not `if_names` itself, then writes the
 * fresh result straight back through `*if_names`. `if_names` (the pointer
 * variable) is never freed -- only the buffer it pointed to before the
 * realloc is, and that stale value is never read again. This is the
 * standard "grow an out-param array" idiom used by real-world code such as
 * hostapd's interface-name collector.
 */

#include <stdlib.h>
#include <string.h>

static int add_if_name(char ***if_names, size_t *if_names_size, const char *arg) {
    char **nnames;

    nnames = realloc(*if_names, (*if_names_size + 1) * sizeof(char *));
    if (nnames == NULL) {
        return -1;
    }
    *if_names = nnames;

    (*if_names)[*if_names_size] = strdup(arg);
    if ((*if_names)[*if_names_size] == NULL) {
        return -1;
    }
    (*if_names_size)++;

    return 0;
}

int main(void) {
    char **if_names = NULL;
    size_t if_names_size = 0;

    if (add_if_name(&if_names, &if_names_size, "eth0") != 0) {
        return 1;
    }
    if (add_if_name(&if_names, &if_names_size, "eth1") != 0) {
        return 1;
    }

    for (size_t i = 0; i < if_names_size; i++) {
        free(if_names[i]);
    }
    free(if_names);

    return 0;
}
