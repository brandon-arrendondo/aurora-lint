/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 *
 * node_obtain() returns through a macro, so its parse holds no `return` and
 * `returns_allocation` falls back to whether the body calls an allocator.
 * It does: `malloc (sizeof ...)`, a space before the parenthesis, is a call
 * to malloc like any other. A text search for "malloc(" missed it, so the
 * caller's dropped result was never tracked.
 */
#include <stdlib.h>

#define RETURN_PTR(p) return (p)

struct node {
    int v;
};

static struct node *node_obtain(void) {
    RETURN_PTR(malloc (sizeof(struct node)));
}

int use_node(int v) {
    struct node *n = node_obtain();
    if (n == NULL) {
        return -1;
    }
    n->v = v;
    return n->v;
}
