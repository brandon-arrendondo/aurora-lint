/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - A file-scope shift amount was overwritten through a pointer
 *
 * `gs` is assigned 3, but the store through `q` replaces it with an
 * unchecked value before the shift.
 */

int read_untrusted(void);

int gs;

int mask(void)
{
    gs = 3;
    int *q = &gs;
    *q = read_untrusted();
    return 1 << gs;
}
