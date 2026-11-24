/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * The loop writes one element per pass through an index that names its
 * counter inside an expression, so five of the ten elements stay
 * uninitialized and the read of all ten is flagged.
 */

#include <stdlib.h>

int partial_through_an_offset_index(void) {
    int *data = malloc(10 * sizeof(int));
    int i;
    int sum = 0;
    if (data == NULL) {
        return 0;
    }
    for (i = 0; i < 5; i++) {
        data[i + 1] = i;
    }
    for (i = 0; i < 10; i++) {
        sum += data[i]; /* VIOLATION */
    }
    free(data);
    return sum;
}
