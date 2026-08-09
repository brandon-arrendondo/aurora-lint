/*
 * Rule: MEM30-C
 * Source: task 402
 * Status: FAIL - Should trigger MEM30-C violation on 'data'
 *
 * Regression: 'data' starts NULL (nullified_vars). One branch of the if
 * allocates and frees it; the other branch (which never touches 'data')
 * leaves the pre-if nullified state unchanged. merge_if_branches must not
 * union that stale nullified state into the merged nullified_vars and mask
 * the real free from the then-branch -- is_freed() checks nullified_vars
 * before freed_vars, so a plain union previously suppressed this hit.
 */

#include <stdlib.h>
#include <stdio.h>

void example(int cond) {
    int *data;
    data = NULL;

    if (cond) {
        data = malloc(sizeof(int));
        free(data);
    }

    // BUG: data was freed in the then-branch; the (implicit) else branch
    // never touches it, so it must not be treated as still-nullified.
    printf("Value: %d\n", *data);
}
