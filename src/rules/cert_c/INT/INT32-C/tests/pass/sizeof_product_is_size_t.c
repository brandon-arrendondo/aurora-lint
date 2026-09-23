/*
 * Rule: INT32-C
 * Source: task 1276 (valkey src/rio.c:622 `sizeof(int) * numconns`)
 * Status: PASS - Should NOT trigger INT32-C violation
 * Reason: `sizeof` yields size_t, so the product is performed in size_t
 *         after `numconns` converts -- unsigned arithmetic, INT30-C's
 *         concern if anything. `infer_type` read "signed" off the `int`
 *         inside `sizeof(int)`'s text and reported a signed multiplication.
 */

#include <stdlib.h>

void *zmalloc(size_t n);

struct rio {
    int *state;
    void **conns;
};

void init_connset(struct rio *r, void **conns, int numconns)
{
    r->conns = zmalloc(sizeof(void *) * numconns);
    r->state = zmalloc(sizeof(int) * numconns);
    (void)conns;
}
