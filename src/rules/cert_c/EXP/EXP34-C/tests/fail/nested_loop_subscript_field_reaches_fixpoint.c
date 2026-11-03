/*
 * Rule: EXP34-C
 * Source: regression
 * Status: FAIL - the null-state analysis converges on nested loops that read
 *         and then clear a field of a subscripted element
 *
 * The inner body reads `a[j].q` and then stores NULL into it. The null-state
 * worklist used to oscillate on this shape without reaching a fixpoint, hit
 * its iteration cap, and lose the file's findings. With the loops analysed to
 * convergence, `last` is still NULL when `n` is zero, and the dereference
 * after the loops reads through it.
 */
#include <stddef.h>

struct item { int x; };
struct slot { struct item *q; };

int drain(struct slot *a, int n) {
    int i, j;
    struct item *last = NULL;
    for (i = 0; i < n; i++)
        for (j = 0; j < n; j++) {
            struct item *p = a[j].q;
            a[j].q = NULL;
            last = p;
        }
    return last->x; /* Expect: here */
}
