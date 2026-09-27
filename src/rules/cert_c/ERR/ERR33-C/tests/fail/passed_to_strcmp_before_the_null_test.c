/*
 * Rule: ERR33-C
 * Status: FAIL - strcmp(p, ...) inside a comparison dereferences the getenv
 * result before `if (!p)` tests it.
 */

#include <stdlib.h>
#include <string.h>

int f(void) {
    char *p = getenv("MODE");
    if (strcmp(p, "fast") == 0) {
        return 2;
    }
    if (!p) {
        return 1;
    }
    return 0;
}
