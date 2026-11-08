/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A branch in the arm stores past the end and returns
 *
 * The store never reaches the access.
 */

int buf[4];
int c;

int element(void)
{
    int i = 1;
#if A
    if (c) {
        i = 9;
        return i;
    }
#endif
    return buf[i];
}
