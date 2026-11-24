/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * The write is indexed by the outer loop's counter inside a one-pass inner
 * loop, so two of the ten elements are written and the read of all ten is
 * flagged.
 */

#include <stdlib.h>

int partial_through_the_outer_counter(void) {
    int *data = malloc(10 * sizeof(int));
    int i, j, k, m = 0;
    int sum = 0;
    if (data == NULL) {
        return 0;
    }
    for (i = 0; i < 2; i++) {
        for (j = 0; j < 1; j++) {
            data[i] = 0;
        }
    }
    for (i = 0; i < 10; i++) {
        sum += data[i]; /* VIOLATION */
    }
    free(data);
    return sum;
}
