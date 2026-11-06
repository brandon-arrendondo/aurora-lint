/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The array the #else arm indexes is not the #if arm's
 *
 * The #if arm declares a four-element `buf` of its own, but the access is
 * in the #else arm, where `buf` is the eight-element file-scope array.
 * Neither of the index's arms reaches past eight elements.
 */

char buf[8];

int element(void)
{
#if defined(B)
    char buf[4];
    buf[0] = 0;
#else
#if defined(A)
    int i = 7;
#else
    int i = 3;
#endif
    return buf[i];
#endif
    return 0;
}
