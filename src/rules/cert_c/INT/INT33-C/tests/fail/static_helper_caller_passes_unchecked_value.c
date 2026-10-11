/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - One caller passes a value nobody checked
 *
 * helper() is static, so its callers are all here. One passes 3, but the
 * other forwards its own parameter n, which may be zero.
 */

static int helper(int a, int d)
{
    return a / d;
}

int use(int a, int n)
{
    return helper(a, 3) + helper(a, n);
}
