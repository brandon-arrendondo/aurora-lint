/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: The guard on an earlier fix's ownership-escape credit. Passing a
 * pointer to a callee is an escape only on POSITIVE evidence from that
 * callee's body that it stores the value somewhere outliving the call.
 * A callee that merely READS the block, one that writes it into a local it
 * does NOT return, and one that stores a DIFFERENT parameter all leave the
 * caller as the sole owner, so the leak must still be reported. Treating any
 * argument pass as an escape would suppress these wholesale, which is the
 * option an earlier fix rejected.
 */

#include <stdlib.h>
#include <string.h>

struct elem {
    struct elem *next;
    void *ptr;
};

/* Reads the block and stores nothing. */
static size_t elem_measure(const struct elem *he) {
    return he->ptr ? 1u : 0u;
}

int leaks_after_read(void) {
    struct elem *he = malloc(sizeof(*he));
    if (he == NULL) {
        return -1;
    }
    he->ptr = NULL;
    if (elem_measure(he) == 0) {
        return -1;
    }
    return 0;
}

/* Writes into a local that never leaves the callee. */
static int elem_stage(struct elem *he) {
    struct elem *scratch = NULL;
    scratch = he;
    return scratch->ptr == NULL;
}

int leaks_after_stage(void) {
    struct elem *he = malloc(sizeof(*he));
    if (he == NULL) {
        return -1;
    }
    he->ptr = NULL;
    return elem_stage(he);
}

/* Stores its FIRST parameter; the second is only read. */
static void elem_adopt(struct elem **anchor, const struct elem *other) {
    struct elem *taken = *anchor;
    taken->ptr = other->ptr;
}

int leaks_unstored_argument(struct elem **anchor) {
    struct elem *he = malloc(sizeof(*he));
    if (he == NULL) {
        return -1;
    }
    he->ptr = NULL;
    elem_adopt(anchor, he);
    return 0;
}
