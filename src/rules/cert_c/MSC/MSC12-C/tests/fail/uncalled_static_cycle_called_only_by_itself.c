/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: FAIL - two statics that only call each other are never executed
 * Expect: default=violation strict=clean pedantic=clean count=2
 *
 * Each has a caller, so the strict and pedantic policies, which read the
 * rule's "no caller" as written, report neither; the default policy
 * reports both as called only from code that never runs.
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

int api(int n)
{
    return n;
}
