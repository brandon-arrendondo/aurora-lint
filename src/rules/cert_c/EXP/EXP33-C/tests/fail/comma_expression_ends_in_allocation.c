/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * A comma expression's value is its last operand: the malloc call.
 */

#include <stdlib.h>

static int calls;

char comma_allocation(void) {
    char *p = (calls++, malloc(8));
    char c = p[0]; /* VIOLATION */
    free(p);
    return c;
}
