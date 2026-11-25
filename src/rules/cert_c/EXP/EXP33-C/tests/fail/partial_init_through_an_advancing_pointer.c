/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * The write's offset is constant, but the loop advances the pointer it is
 * taken from, so each pass writes the next element: five of the ten are
 * written, and the read of all ten is flagged.
 */

#include <stdlib.h>

int partial_through_an_advanced_subscript(void) {
    int *data = malloc(10 * sizeof(int));
    int i;
    int sum = 0;
    if (data == NULL) {
        return 0;
    }
    for (i = 0; i < 5; i++) {
        data[0] = 0;
        data++;
    }
    for (i = 0; i < 10; i++) {
        sum += data[i]; /* VIOLATION */
    }
    return sum;
}

int partial_through_a_pointer_the_update_advances(void) {
    int *data = malloc(10 * sizeof(int));
    int i;
    int sum = 0;
    if (data == NULL) {
        return 0;
    }
    for (i = 0; i < 5; i++, data++) {
        *data = 0;
    }
    for (i = 0; i < 10; i++) {
        sum += data[i]; /* VIOLATION */
    }
    return sum;
}
