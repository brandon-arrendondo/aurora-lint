/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - The index was overwritten through a pointer
 *
 * `i` is initialised to 0, but the store through `q` replaces it with an
 * unchecked value before the subscript.
 */

int read_untrusted(void);

int fill(void)
{
    int buf[10];
    int i = 0;
    int *q = &i;
    *q = read_untrusted();
    buf[i] = 1;
    return buf[0];
}
