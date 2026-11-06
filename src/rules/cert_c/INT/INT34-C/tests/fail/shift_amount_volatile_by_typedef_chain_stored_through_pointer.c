/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - An amount volatile through a chain of typedefs may change after the store
 *
 * `vv` is `vint`, which is volatile, so the value the shift reads need
 * not be the 2 just stored.
 */

typedef volatile int vint;
typedef vint vv;

int mask(void)
{
    vv s = 40;
    vv *q = &s;
    *q = 2;
    return 1 << s;
}
