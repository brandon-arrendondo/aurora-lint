/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - The array in the access's own arm is declared before it
 *
 * The first declaration the access can see is the four-element one in its
 * arm. The incomplete one after the #endif comes too late to be it.
 */

#ifdef WITH_BUF
char buf[4];

int element(void)
{
    return buf[5];
}
#endif

extern char buf[];
