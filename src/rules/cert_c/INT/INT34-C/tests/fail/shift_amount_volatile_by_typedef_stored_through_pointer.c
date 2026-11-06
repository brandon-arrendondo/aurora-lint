/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - An amount volatile through its typedef may change after the store
 *
 * `vint` is a volatile type, so the value the shift reads need not be
 * the 2 just stored.
 */

typedef volatile int vint;

int mask(void)
{
    vint s = 40;
    vint *q = &s;
    *q = 2;
    return 1 << s;
}
