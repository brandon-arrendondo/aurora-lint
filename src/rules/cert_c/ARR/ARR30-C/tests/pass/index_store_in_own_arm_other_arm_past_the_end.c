/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The other arm's store is not this access's
 *
 * The store of 9 is in the arm that does not hold the access.
 */

int buf[4];

int element(void)
{
    int i;
#if defined(A)
    i = 1;
    return buf[i];
#else
    i = 9;
    return i;
#endif
}
