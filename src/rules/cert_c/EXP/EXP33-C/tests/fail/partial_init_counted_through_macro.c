/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * The element count comes through a macro's expansion: ALLOC_INTS(10) is
 * malloc(10 * sizeof(int)), and the loop writes only the first five.
 */

#include <stdlib.h>

#define ALLOC_INTS(n) malloc((n) * sizeof(int))

int partial_through_macro(void) {
    int *data = ALLOC_INTS(10);
    int i;
    int sum = 0;
    for (i = 0; i < 5; i++) {
        data[i] = i;
    }
    for (i = 0; i < 10; i++) {
        sum += data[i]; /* VIOLATION */
    }
    free(data);
    return sum;
}
