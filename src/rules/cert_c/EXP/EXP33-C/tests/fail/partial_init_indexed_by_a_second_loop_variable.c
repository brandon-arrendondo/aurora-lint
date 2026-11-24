/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * The loop condition tests k, but the write is indexed by i, which the loop
 * steps alongside it. Two of the ten elements are written, so the read of
 * all ten is flagged.
 */

#include <stdlib.h>

int partial_through_a_second_loop_variable(void) {
    int *data = malloc(10 * sizeof(int));
    int i, j, k, m = 0;
    int sum = 0;
    if (data == NULL) {
        return 0;
    }
    for (i = 0, k = 0; k < 2; k++, i++) {
        data[i] = 0;
    }
    for (i = 0; i < 10; i++) {
        sum += data[i]; /* VIOLATION */
    }
    free(data);
    return sum;
}
