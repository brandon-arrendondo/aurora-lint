/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - The shift amount was overwritten through a pointer
 *
 * `s` is initialised to 3, but the store through `q` replaces it with an
 * unchecked value before the shift: the initialiser says nothing about
 * the amount the shift uses.
 */

int read_untrusted(void);

int mask(void)
{
    int s = 3;
    int *q = &s;
    *q = read_untrusted();
    return 1 << s;
}
