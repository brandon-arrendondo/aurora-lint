/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - A function-like macro assigns the file-scope amount
 *
 * `SET` expands to an assignment of `gs`, so the shift is by the
 * unchecked value, not 3.
 */

#define SET(x) (gs = (x))

int read_untrusted(void);

int gs;

int mask(void)
{
    gs = 3;
    SET(read_untrusted());
    return 1 << gs;
}
