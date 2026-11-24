/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: FAIL - the root of a chain nothing calls is reported in every policy
 *
 * The default policy also reports leaf, called only from code that never
 * runs; the strict and pedantic policies do not, since leaf has a caller.
 * live_leaf is called from live code and is reported by none.
 */
static int leaf(int n)
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
