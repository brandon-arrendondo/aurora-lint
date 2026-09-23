/*
 * Rule: ARR30-C
 * Source: real-world (surfaced by the scope-resolution fix; hostap
 *         src/drivers/linux_ioctl.c `char path[128], brlink[128], *pos;`
 *         is the corpus shape)
 * Status: FAIL - `b[9]` writes past an eight-element array.
 *
 * The prescan's declaration extractor returned after the FIRST array
 * declarator of a declaration, so in `char a[8], b[8], *p;` only `a` was
 * ever tracked and `b` was invisible to every bounds check. Resolving the
 * occurrence `b` to its own declarator (ADR-0006) sizes it from the
 * declaration directly, whether or not the prescan recorded it.
 */

int f(void)
{
    char a[8], b[8], *p;
    p = a;
    a[7] = 1;
    b[9] = 2;
    return p[0];
}
