/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM30-C violation
 */

/*
 * Rule: MEM30-C - Do not access freed memory
 * Status: PASS
 * Reason: Freeing one STRUCT field must not poison sibling fields or the base.
 *         Struct fields are independent allocations (unlike union members,
 *         which overlap in storage). Freeing data->state.range does not
 *         invalidate data->state.host or data->multi. Regression for the
 *         struct-field-free cascade FP (task 181); the union-member aliasing
 *         heuristic is now gated on genuinely union-typed variables.
 */

#include <stdlib.h>
#include <stdio.h>

struct state {
    char *range;
    char *host;
};

struct easy {
    struct state state;
    int *multi;
};

void reset(struct easy *data) {
    free(data->state.range);
    data->state.range = NULL;

    /* Sibling field of the same struct - NOT the freed object. */
    if (data->state.host != NULL) {
        printf("host: %s\n", data->state.host);
    }

    /* Unrelated field on the base - NOT the freed object. */
    if (data->multi != NULL) {
        *data->multi = 0;
    }
}
