/*
 * Rule: API00-C
 * Source: testcases
 * Status: PASS - Should NOT trigger API00-C violation
 *
 * LOCAL_FN is this project's own spelling for internal linkage: its
 * `#define` expands to `static`. A static function is not a public API, so
 * API00-C's parameter-validation contract does not apply to it.
 */

struct point { int x; int y; };

#define LOCAL_FN static

LOCAL_FN int point_sum(const struct point *p)
{
    return p->x + p->y;
}

int use_point(void)
{
    struct point pt = { 1, 2 };
    return point_sum(&pt);
}
