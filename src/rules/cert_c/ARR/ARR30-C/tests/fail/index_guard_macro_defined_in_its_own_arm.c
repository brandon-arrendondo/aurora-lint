/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - An #ifndef defining its own name is not one question twice
 * Expect: count=1
 *
 * The first chain defines H, so the access compiles with the store of 9.
 */

int buf[4];
int c;

int element(void)
{
#ifndef H
#define H
    int i = 9;
#else
    int i = 1;
#endif
#ifndef H
    return 0;
#else
    return buf[i];
#endif
}
