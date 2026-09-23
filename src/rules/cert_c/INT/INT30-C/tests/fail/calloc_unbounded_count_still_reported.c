/*
 * Rule: INT30-C
 * Source: task 1325 (companion to pass/task_1325_calloc_constant_product_cannot_wrap.c)
 * Status: FAIL - Should trigger INT30-C violation
 * Reason: Proving a calloc() product cannot wrap must not reach a count
 *         the analysis cannot bound: a parameter, a global, a value
 *         computed from a parameter. And a product that IS computed and
 *         wraps a 32-bit size_t stays reported even though both operands
 *         are constants -- the constant clause never overrides a computed
 *         wrap.
 */

#include <stdlib.h>

#define HUGE_COUNT 1073741825

struct cfg { int a; char b[64]; };

extern size_t g_count;

/* VIOLATION: the count is a parameter nothing bounds */
void *from_param(size_t n) { return calloc(n, sizeof(struct cfg)); }

/* VIOLATION: the count is a global nothing bounds */
void *from_global(void) { return calloc(g_count, sizeof(int)); }

/* VIOLATION: the count was computed from an unbounded parameter */
void *from_derived(size_t n)
{
    size_t k = n + 1;
    return calloc(k, sizeof(int));
}

/* VIOLATION: constant, and the product 4294967300 wraps a 32-bit size_t */
void *constant_wrap(void) { return calloc(HUGE_COUNT, sizeof(int)); }
