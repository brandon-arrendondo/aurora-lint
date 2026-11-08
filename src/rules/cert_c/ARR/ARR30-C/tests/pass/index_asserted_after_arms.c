/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - An assertion on the index stands before the access
 *
 * The reading does not follow it, and claims nothing.
 */

#define CHECK(x) ((x) ? (void)0 : (void)0)
int buf[4];
int c;

int element(void)
{
    int i = 1;
#if A
    i = 9;
#endif
    CHECK(i < 4);
    return buf[i];
}
