/*
 * Rule: EXP34-C
 * Source: regression
 * Status: PASS - the null-state analysis converges on nested loops that read
 *         and then clear a field of a subscripted element
 *
 * The same loops as the failing twin: the inner body reads `a[j].q` and then
 * stores NULL into it, the shape on which the null-state worklist used to
 * oscillate until its iteration cap. Here the pointer the loops leave behind
 * is checked before it is dereferenced.
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
    if (last == NULL)
        return 0;
    return last->x;
}
