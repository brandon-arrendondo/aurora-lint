/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The helper may be called through a stored pointer
 *
 * Every direct call passes 3, but the function's address is stored, so a
 * call through the pointer, elsewhere, may pass anything.
 */

static int helper(int a, int d)
{
    return a / d;
}

int (*op)(int, int) = helper;

int use(int a)
{
    return helper(a, 3);
}
