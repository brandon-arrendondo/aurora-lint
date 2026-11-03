/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: PASS - The amount is assigned after the store through the pointer
 *
 * The store through `q` runs before `s = 3`, so the shift is by 3.
 */

int read_untrusted(void);

int mask(void)
{
    int s;
    int *q = &s;
    *q = read_untrusted();
    s = 3;
    return 1 << s;
}
