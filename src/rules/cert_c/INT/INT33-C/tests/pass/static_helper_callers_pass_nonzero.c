/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - Every caller of the static helper passes a non-zero value
 *
 * helper() has internal linkage and its address is never taken, so the
 * calls here are all its calls. Each passes a value proven non-zero at the
 * call: a constant on either side of zero, or a parameter the caller checked.
 * The value is judged as it would be if the caller's code were written
 * inline (ADR-0011).
 */

static int helper(int a, int d)
{
    return a / d;
}

int use(int a, int n)
{
    int r = helper(a, 3) + helper(a, -7);
    if (n != 0)
        r += helper(a, n);
    return r;
}
