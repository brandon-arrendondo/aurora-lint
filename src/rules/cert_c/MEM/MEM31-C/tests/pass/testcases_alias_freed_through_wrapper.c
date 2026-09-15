/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * A free through a project-local wrapper releases the block for every name
 * holding it, exactly as a literal `free()` does. Only the literal-`free`
 * path walked the alias set, so `release(buf)` credited `buf` and left the
 * alias `o` looking live until the function returned.
 */

#include <stdlib.h>

static void release(void *p) {
    free(p);
}

int copy_first(unsigned int len) {
    char *buf;
    char *o;

    buf = malloc(len);
    if (buf == NULL) {
        return -1;
    }
    o = buf;
    o[0] = 'x';
    release(buf);
    return 0;
}
