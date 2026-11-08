/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The other arm's index is not this access's
 *
 * The access is in the #else arm, which declares the in-bounds index. The
 * #if arm's 9 never compiles with it.
 */

int buf[4];

int element(void)
{
#if defined(A)
    int i = 9;
    return i;
#else
    int i = 1;
    return buf[i];
#endif
}
