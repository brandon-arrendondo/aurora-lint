/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: The other half of task 1294's evaluation-order work, and a
 * recall gap rather than a false positive. A callee that releases its
 * argument only on the path where it SUCCEEDS has not taken the block when it
 * returns NULL -- so the caller still owns it, and a bare `return` on that
 * branch leaks it. While the freed mark was applied unconditionally this went
 * unreported: the block looked already dead on every path.
 */

#include <stdlib.h>

static char *rehash(char *old) {
    char *n = malloc(64);

    if (!n) {
        return NULL; /* returns BEFORE releasing old */
    }
    free(old);
    return n;
}

extern char *make_buf(void);

int leak_on_the_failure_path(void) {
    char *buf = make_buf();

    if (!buf) {
        return -1;
    }
    char *fresh = rehash(buf);
    if (!fresh) {
        return -1; /* VIOLATION: rehash did not take 'buf' on this path */
    }
    free(fresh);
    return 0;
}
