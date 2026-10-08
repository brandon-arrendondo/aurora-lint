/*
 * Rule: MEM30-C
 * Source: synthetic
 * Status: PASS under the default and strict presets; VIOLATION under pedantic
 * Expect: default=clean strict=clean pedantic=violation
 *
 * The branch frees `p` and calls exit(), which never returns in a hosted
 * environment (C11 7.22.4.4), so the later use and free are fine. The
 * pedantic preset trusts only a declared library, and this fixture declares
 * none, so nothing says this exit() does not return (stdlib_noreturn), and
 * the freed `p` reaches the join.
 */

#include <stdlib.h>

void use(char *p);

int exit_in_then(int rc)
{
    char *p = malloc(16);
    if (rc != 0) {
        free(p);
        exit(1);
    }
    use(p);
    free(p);
    return 0;
}
