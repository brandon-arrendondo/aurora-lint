/*
 * Rule: PRE02-C
 * Source: testcases
 * Status: FAIL - Should trigger PRE02-C violation
 *
 * A comment inside the replacement list is only white space: the list is
 * still `a + b`, so `2 * SUM(x, y)` expands to `2 * x + y`.
 */

#define SUM(a, b) a /* first */ + b /* VIOLATION */

int twice_sum(int x, int y)
{
    return 2 * SUM(x, y);
}
