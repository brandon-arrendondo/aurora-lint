/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: FAIL - a static only a dead cycle calls is never executed either
 * Expect: default=violation strict=clean pedantic=clean count=3
 */
static int odd(int n);

static int leaf(int n) /* Expect: here */
{
    return n * 2;
}

static int even(int n) /* Expect: here */
{
    return n == 0 ? leaf(n) : odd(n - 1);
}

static int odd(int n) /* Expect: here */
{
    return n == 0 ? 0 : even(n - 1);
}

int api(int n)
{
    return n;
}
