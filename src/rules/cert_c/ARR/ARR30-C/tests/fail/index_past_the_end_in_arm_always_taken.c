/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - An arm always taken stores past the end
 * Expect: count=1
 *
 * The file defines the macro, so the store always runs.
 */

#define B
int buf[4];
int c;

int element(void)
{
    int i = 1;
#ifdef B
    i = 9;
#endif
    return buf[i];
}
