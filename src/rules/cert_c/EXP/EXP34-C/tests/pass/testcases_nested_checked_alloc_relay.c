/*
 * Rule: EXP34-C
 * Source: testcases (hostap EXP34-C parameter cohort)
 * Status: PASS - the caller checks the allocation and diverges on failure, so
 *         `sink`'s parameter is non-null at every reachable call site and its
 *         unchecked dereference of that parameter is the caller's contract
 *         being honoured, not a defect.
 *
 * The guard is NESTED and diverges by `goto`, which is hostap's house style
 * (src/ap/ieee802_11.c handle_auth). A caller-side null check written this way
 * used to be invisible to the prescan's call-site voter, so the allocator's
 * maybe-null state became the callee's parameter state.
 */

#include <stdio.h>
#include <stdlib.h>

void sink(int *ptr) {
    *ptr = 100;
    printf("Value: %d\n", *ptr);
}

int relay(int flag) {
    int *data = NULL;

    if (flag) {
        data = malloc(sizeof(int));
        if (!data)
            goto fail;
        sink(data);
        free(data);
    }

    return 0;

fail:
    return -1;
}
