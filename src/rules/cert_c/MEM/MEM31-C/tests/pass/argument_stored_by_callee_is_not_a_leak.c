/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: Handing a block to a callee that STORES it somewhere
 * outliving the call transfers ownership; the allocating function is no
 * longer the only owner and must not be reported as leaking it at a later
 * return. Three destinations qualify, one per shape `stores_params` credits:
 * through another PARAMETER (curl's hash_elem_link `*he_anchor = he`), into a
 * FILE-SCOPE variable (hostap's eap_peer_method_register `eap_methods =
 * method`), and into a local the callee RETURNS (curl's hash_elem_create
 * `he->ptr = p` under `return he`). The last also arrives through a
 * forwarding wrapper, so the transitive edge carries it. An earlier fix.
 */

#include <stdlib.h>

struct elem {
    struct elem *next;
    void *ptr;
};

/* Stored through a parameter: `*anchor` outlives this call. */
static void elem_link(struct elem **anchor, struct elem *he) {
    he->next = *anchor;
    *anchor = he;
}

int add_to_list(struct elem **anchor) {
    struct elem *he = malloc(sizeof(*he));
    if (he == NULL) {
        return -1;
    }
    he->ptr = NULL;
    elem_link(anchor, he);
    return 0;
}

/* Stored into a file-scope variable, on one arm only: the register-or-free
   contract, where neither the free nor the store is unconditional. */
static struct elem *registry;

static int method_register(struct elem *method) {
    if (method->ptr == NULL) {
        free(method);
        return -1;
    }
    registry = method;
    return 0;
}

int register_method(void *payload) {
    struct elem *m = malloc(sizeof(*m));
    if (m == NULL) {
        return -1;
    }
    m->ptr = payload;
    method_register(m);
    return 0;
}

/* Stored into a local the callee returns, reached through a forwarding
   wrapper so the transitive edge is what carries it. */
static struct elem *elem_create(void *p) {
    struct elem *he = malloc(sizeof(*he));
    if (he) {
        he->next = NULL;
        he->ptr = p;
    }
    return he;
}

static struct elem *hash_add(struct elem **anchor, void *p) {
    struct elem *he = elem_create(p);
    if (he == NULL) {
        return NULL;
    }
    elem_link(anchor, he);
    return he;
}

int store_payload(struct elem **anchor) {
    char *payload = malloc(32);
    if (payload == NULL) {
        return -1;
    }
    hash_add(anchor, payload);
    return 0;
}
