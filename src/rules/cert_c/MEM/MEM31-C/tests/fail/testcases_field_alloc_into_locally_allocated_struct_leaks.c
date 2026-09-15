/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: FAIL
 * Reason: unlike a local bound to a lookup/registry accessor (task 1200,
 * see the companion PASS case), a struct THIS function directly allocated
 * with malloc() is unambiguously its own -- an allocation into one of its
 * fields is still this function's own responsibility to free.
 */

#include <stdlib.h>

struct holder {
    char *label;
};

int make_holder(const char *text) {
    struct holder *h = malloc(sizeof(struct holder));
    if (h == NULL) {
        return -1;
    }

    h->label = strdup(text);
    if (h->label == NULL) {
        free(h);
        return -1;
    }

    /* h and h->label are both leaked here - MEMORY LEAK (h->label at
     * least, since h itself is a separate, already-covered leak shape) */
    return 0;
}
