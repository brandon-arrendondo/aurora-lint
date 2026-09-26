/*
 * Rule: API00-C
 * Source: testcases
 * Status: FAIL - Should trigger API00-C violation
 *
 * PRIVATE is spelled like a linkage macro, but its `#define` expands to
 * nothing, so point_sum is an external function that dereferences its
 * parameter unvalidated. The spelling alone does not make it static.
 */

struct point { int x; int y; };

#define PRIVATE

PRIVATE int point_sum(const struct point *p)
{
    return p->x + p->y;  /* VIOLATION: p is not validated */
}
