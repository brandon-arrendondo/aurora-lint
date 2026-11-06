/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - An amount volatile through a function's own typedef may change after the store
 *
 * `vint` is a volatile type defined in the function, so the value the
 * shift reads need not be the 2 just stored.
 */

int mask(void)
{
    typedef volatile int vint;
    vint s = 40;
    vint *q = &s;
    *q = 2;
    return 1 << s;
}
