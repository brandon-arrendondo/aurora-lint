/*
 * Rule: MSC13-C
 * Source: synthetic
 * Status: FAIL - `r = -1;` is an assignment, and every path, the `goto` included, overwrites it before a read
 */

int get(void);

int f(void)
{
    int r;
    r = -1;
    r = get();
    if (r)
        goto out;
    r = 0;
out:
    return r;
}
