/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A store that always runs decides the arms' values
 *
 * Neither arm's value survives the store of 1.
 */

int buf[4];

int element(void)
{
#if defined(A)
    int i = 9;
#else
    int i = 8;
#endif
    i = 1;
    return buf[i];
}
