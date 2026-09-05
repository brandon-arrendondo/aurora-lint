/*
 * Rule: INT32-C
 * Source: testcases
 * Status: FAIL - Should trigger INT32-C violation
 * Description: Companion to pass/alloc_arg_no_arithmetic.c (task 915).
 * Narrowing the allocation-argument overflow check to the positions that
 * actually carry a size must leave those positions checked: malloc()
 * argument 1, calloc() arguments 1 and 2, and realloc() argument 2.
 *
 * The wrapping count is spelled as the literal INT_MAX/2 + 2 throughout:
 * the generated unit test calls the rule without the CLI's macro map, so
 * a <limits.h> spelling would be unevaluable here.
 */

#include <stdlib.h>

void *malloc_size_wraps(void) {
    int data = 1073741825;
    /* VIOLATION: product wraps a 32-bit size_t */
    return malloc(data * sizeof(int));
}

void *calloc_count_wraps(void) {
    int data = 1073741825;
    /* VIOLATION: first argument is the element count and wraps */
    return calloc(data * sizeof(int), 1);
}

void *calloc_size_wraps(void) {
    int data = 1073741825;
    /* VIOLATION: second argument is the element size and wraps */
    return calloc(1, data * sizeof(int));
}

void *realloc_size_wraps(void *p) {
    int data = 1073741825;
    /* VIOLATION: second argument is the new size and wraps */
    return realloc(p, data * sizeof(int));
}
