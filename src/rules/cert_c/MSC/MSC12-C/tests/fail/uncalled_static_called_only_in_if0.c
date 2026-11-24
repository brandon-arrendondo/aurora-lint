/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: FAIL - the only call is in an arm no configuration compiles
 */
static void trace(int v) /* Expect: here */
{
    (void)v;
}

void api(int v)
{
#if 0
    trace(v);
#endif
    (void)v;
}
