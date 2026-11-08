/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A guarded array keeps its size past a declaration with none
 *
 * The index fits the 8 the first declaration states.
 */

#ifndef H
int buf[8];
extern int buf[];
#endif

int element(void)
{
    return buf[7];
}
