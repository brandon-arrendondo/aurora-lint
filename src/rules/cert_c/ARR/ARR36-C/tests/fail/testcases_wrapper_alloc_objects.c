/*
 * Rule: ARR36-C
 * Source: testcases
 * Status: FAIL - Should trigger ARR36-C violation
 */

/*
 * Rule: ARR36-C - Do not subtract or compare two pointers that do not refer to
 *       the same array
 * Status: FAIL
 * Reason: The reporting-direction half of putting allocator wrappers in the
 *         allocation list. Every allocation is its own object, so two distinct
 *         os_zalloc calls compared against each other are two objects -- a
 *         violation, where before the wrapper was recognized NEITHER operand
 *         had a base and nothing was reported.
 */

#include <stddef.h>

void *os_zalloc(size_t size);

ptrdiff_t wrapper_alloc_diff(void)
{
    int *a = os_zalloc(10 * sizeof(int));
    int *b = os_zalloc(10 * sizeof(int));

    if (a == NULL || b == NULL) {
        return 0;
    }

    return b - a;  /* VIOLATION - two distinct allocated objects */
}
