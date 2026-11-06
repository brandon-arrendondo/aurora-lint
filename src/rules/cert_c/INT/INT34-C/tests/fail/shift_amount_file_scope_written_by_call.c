/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - A called function rewrites the file-scope shift amount
 *
 * `refresh` assigns `gs` an unchecked value, and it runs between the
 * assignment of 3 and the shift.
 */

int read_untrusted(void);

int gs;

void refresh(void)
{
    gs = read_untrusted();
}

int mask(void)
{
    gs = 3;
    refresh();
    return 1 << gs;
}
