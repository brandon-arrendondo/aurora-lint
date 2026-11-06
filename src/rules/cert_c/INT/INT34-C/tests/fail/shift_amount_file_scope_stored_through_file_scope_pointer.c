/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - A static shift amount was overwritten through a file-scope pointer
 *
 * `gp` holds the address of `gs` from its initialiser, so the store
 * through it replaces the 3 with an unchecked value before the shift.
 */

int read_untrusted(void);

static int gs;
static int *gp = &gs;

int mask(void)
{
    gs = 3;
    *gp = read_untrusted();
    return 1 << gs;
}
