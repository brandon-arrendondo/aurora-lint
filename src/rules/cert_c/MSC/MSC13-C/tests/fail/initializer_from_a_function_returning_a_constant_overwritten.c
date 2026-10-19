/*
 * Rule: MSC13-C
 * Source: synthetic
 * Status: FAIL - a call is no default value even when the callee only returns a constant
 */

int three(void)
{
    return 3;
}

int f(int c)
{
    int x = three();
    x = c;
    return x;
}
