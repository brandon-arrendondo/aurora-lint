/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A guarded array keeps its size past a tentative declaration with none
 * Expect: count=1
 *
 * The second declaration names the same array of 8.
 */

#ifndef H
int buf[8];
int buf[];
#endif

int element(void)
{
    return buf[9];
}
