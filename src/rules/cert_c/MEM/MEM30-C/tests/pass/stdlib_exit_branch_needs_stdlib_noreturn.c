/*
 * Rule: MEM30-C
 * Source: synthetic
 * Status: PASS under the default preset; VIOLATION under strict
 * Expect: default=clean strict=violation
 *
 * The branch frees `p` and calls exit(), which never returns in a hosted
 * environment (C11 7.22.4.4), so the later use and free are fine. The
 * strict preset declares a freestanding environment with no library model,
 * where nothing says this exit() does not return (stdlib_noreturn), so the
 * freed `p` reaches the join.
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
