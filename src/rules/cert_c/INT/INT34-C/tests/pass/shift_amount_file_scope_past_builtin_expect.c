/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: PASS - __builtin_expect writes no file-scope object
 *
 * `__builtin_expect` is a compiler builtin, not a call that could
 * assign `gs`, so the shift is by 3.
 */

int gs;

int mask(void)
{
    gs = 3;
    if (__builtin_expect(gs, 1))
        return 1 << gs;
    return 0;
}
