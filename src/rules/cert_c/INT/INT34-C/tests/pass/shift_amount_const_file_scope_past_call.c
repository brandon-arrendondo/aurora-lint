/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: PASS - A const file-scope amount is not written by a call
 *
 * `gs` is a const object, so the call between its definition and the
 * shift cannot change it, and the shift is by 3.
 */

void refresh(void);

static const int gs = 3;

int mask(void)
{
    refresh();
    return 1 << gs;
}
