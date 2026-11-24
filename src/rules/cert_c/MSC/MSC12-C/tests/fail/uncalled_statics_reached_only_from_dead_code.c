/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: FAIL - a cycle of statics nothing live calls, and a static only a dead static calls, are never executed
 */
static int odd(int n);

static int even(int n) /* Expect: here */
{
    return n == 0 ? 1 : odd(n - 1);
}

static int odd(int n) /* Expect: here */
{
    return n == 0 ? 0 : even(n - 1);
}

static int leaf(int n) /* Expect: here */
{
    return n * 2;
}

static int dead_root(int n) /* Expect: here */
{
    return leaf(n);
}

static int live_leaf(int n)
{
    return n + 1;
}

static int live_middle(int n)
{
    return live_leaf(n);
}

int api(int n)
{
    return live_middle(n);
}
