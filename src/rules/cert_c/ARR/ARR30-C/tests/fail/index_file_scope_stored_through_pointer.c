/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A file-scope index was overwritten through a pointer
 * Expect: count=1
 *
 * `gi` is assigned 2, but the store through `q` replaces it with an
 * unchecked value before the access.
 */

int read_untrusted(void);

int gi;
int buf[4];

int element(void)
{
    gi = 2;
    int *q = &gi;
    *q = read_untrusted();
    return buf[gi]; /* Expect: here */
}
