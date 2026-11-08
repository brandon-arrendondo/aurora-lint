/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The access is compiled only with the arm declaring eight elements
 *
 * Both conditionals open on `#if A`, so the #else arm's four elements and
 * the access never compile together.
 */

int element(void)
{
    int i = 7;
#if A
    int buf[8];
#else
    int buf[4];
#endif
#if A
    return buf[i];
#else
    return 0;
#endif
}
