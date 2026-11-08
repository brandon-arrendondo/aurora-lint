/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - Every configuration leaves an index in bounds
 *
 * Neither arm declares the index when A and B are undefined, and the outer
 * index is in bounds too.
 */

int buf[4];

int element(void)
{
    int i = 3;
    {
#if defined(A)
        int i = 1;
#elif defined(B)
        int i = 2;
#endif
        return buf[i];
    }
}
