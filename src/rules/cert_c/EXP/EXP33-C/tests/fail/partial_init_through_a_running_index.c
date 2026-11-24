/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * The loop writes one element per pass through a running index that is not
 * its counter, so two of the ten elements are written and the read of all
 * ten is flagged.
 */

#include <stdlib.h>

int partial_through_a_running_index(void) {
    int *data = malloc(10 * sizeof(int));
    int i, j, k, m = 0;
    int sum = 0;
    if (data == NULL) {
        return 0;
    }
    for (k = 0; k < 2; k++) {
        data[m++] = 0;
    }
    for (i = 0; i < 10; i++) {
        sum += data[i]; /* VIOLATION */
    }
    free(data);
    return sum;
}
