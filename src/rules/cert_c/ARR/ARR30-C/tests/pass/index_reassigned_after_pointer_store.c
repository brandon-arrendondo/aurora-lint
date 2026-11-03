/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The index is assigned after the store through the pointer
 *
 * The store through `q` runs before `i = 2`, so the subscript is 2.
 */

int read_untrusted(void);

int fill(void)
{
    int buf[10];
    int i;
    int *q = &i;
    *q = read_untrusted();
    i = 2;
    buf[i] = 1;
    return buf[0];
}
