/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - A nested function stores through the pointer after the store
 *
 * The GNU nested function `n` stores 40 through `q`, and it runs after
 * `*q = 2`.
 */

int mask(void)
{
    int s = 40;
    int *q = &s;
    void n(void)
    {
        *q = 40;
    }
    *q = 2;
    n();
    return 1 << s;
}
