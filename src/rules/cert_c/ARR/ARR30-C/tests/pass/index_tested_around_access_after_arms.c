/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A test holding the access keeps the index in bounds
 *
 * The access runs only below the bound.
 */

int buf[4];
int c;

int element(void)
{
    int i = 1;
#if A
    i = 9;
#endif
    if (i < 4) {
        return buf[i];
    }
    return 0;
}
