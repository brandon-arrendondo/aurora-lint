/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The store writes the inner block's own variable
 *
 * The inner `i` is a separate object: storing through a pointer to it
 * leaves the outer `i` holding 0.
 */

int read_untrusted(void);

int fill(void)
{
    int buf[10];
    int i = 0;
    {
        int i = 0;
        int *q = &i;
        *q = read_untrusted();
        (void)i;
    }
    buf[i] = 1;
    return buf[0];
}
