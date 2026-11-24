/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: FAIL - a call from its own body is no caller
 */
static int countdown(int n) /* Expect: here */
{
    return n <= 0 ? 0 : countdown(n - 1);
}

int api(int n)
{
    return n;
}
