/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: PASS - each static is called, one through a prototype declared before it
 */
static int twice(int v);

static int add_one(int v)
{
    return v + 1;
}

int api(int v)
{
    return twice(add_one(v));
}

static int twice(int v)
{
    return v * 2;
}
