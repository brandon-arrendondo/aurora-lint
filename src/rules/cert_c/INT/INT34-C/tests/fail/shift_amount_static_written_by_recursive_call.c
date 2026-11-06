/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - A recursive call leaves the static amount at 40
 *
 * Only `f` assigns `s`, but `f` calls itself between `s = 3` and the
 * shift, and the inner call ends by setting `s` to 40, so every outer
 * shift is by 40.
 */

static int s;

int f(int n)
{
    int r;
    s = 3;
    if (n)
        f(n - 1);
    r = 1 << s;
    s = 40;
    return r;
}
