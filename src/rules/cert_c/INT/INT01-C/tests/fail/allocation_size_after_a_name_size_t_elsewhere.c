/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: FAIL - an int size after a count named like a size_t elsewhere
 *
 * A size_t n is declared in an earlier block, but that does not make the n
 * in the other block a size_t, and the scan goes on to len, the element
 * size, which is held in an int.
 */
#include <stdlib.h>

int wanted(void);

void *make_buffers(int twice) {
    void *p = NULL;
    if (twice) {
        size_t n = 16;
        p = malloc(n);
    } else {
        int n = wanted();
        int len = wanted();
        p = calloc(n, len);
    }
    return p;
}
