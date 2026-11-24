/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: FAIL - an uncalled static with an empty body is reported once, as uncalled
 * Expect: count=1
 */
static void noop(void)
{
}

int api(void)
{
    return 0;
}
