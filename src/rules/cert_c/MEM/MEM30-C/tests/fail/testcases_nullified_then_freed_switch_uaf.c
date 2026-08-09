/*
 * Rule: MEM30-C
 * Source: task 402
 * Status: FAIL - Should trigger MEM30-C violation on 'data'
 *
 * Regression: same pattern as testcases_nullified_then_freed_branch_uaf.c
 * but through merge_switch_arms (task 398) instead of merge_if_branches.
 * 'data' starts NULL; one case allocates and frees it, other cases/the
 * implicit fallthrough-to-end path never touch it, so the merge must not
 * let their stale nullified state mask the free.
 */

#include <stdlib.h>
#include <stdio.h>

void example(int which) {
    int *data;
    data = NULL;

    switch (which) {
        case 1:
            data = malloc(sizeof(int));
            free(data);
            break;
        case 2:
            printf("no-op case\n");
            break;
    }

    // BUG: data was freed in case 1; no default/other case re-nulls it.
    printf("Value: %d\n", *data);
}
