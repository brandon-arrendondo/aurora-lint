/*
 * Rule: EXP34-C
 * Source: testcases (hostap EXP34-C parameter cohort)
 * Status: FAIL - `if (data) return -1;` diverges when data is NON-null, so
 *         `data` is NULL at the relay below it. The guard must not be read as
 *         establishing non-null: the check on the call-site voting path is
 *         polarity-aware for exactly this reason.
 */

#include <stdio.h>

void sink(int *ptr) {
    *ptr = 100;
    printf("Value: %d\n", *ptr);
}

int relay(int flag) {
    int *data = NULL;

    if (flag) {
        if (data)
            return -1;
        sink(data);
    }

    return 0;
}
