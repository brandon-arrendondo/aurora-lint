/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 *
 * node_obtain() returns through a macro, so its parse holds no `return` and
 * `returns_allocation` falls back to whether the body calls an allocator.
 * It calls NODE_ALLOC, a function-like macro whose replacement list calls
 * calloc, so it allocates, and the caller's dropped result is a leak.
 */
#include <stdlib.h>

#define RETURN_PTR(p) return (p)
#define NODE_ALLOC(size) calloc(1, (size))

struct node {
    int v;
};

static struct node *node_obtain(void) {
    RETURN_PTR(NODE_ALLOC(sizeof(struct node)));
}

int use_node(int v) {
    struct node *n = node_obtain();
    if (n == NULL) {
        return -1;
    }
    n->v = v;
    return n->v;
}
