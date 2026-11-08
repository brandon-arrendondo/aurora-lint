/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A macro redefined between chains makes them two questions
 *
 * The store of 1 and the access are both compiled, and 9 does not reach it.
 */

int buf[4];
int c;

int element(void)
{
    int i = 9;
#define A 1
#if A
    i = 1;
#endif
#undef A
#define A 0
#if A
    return 0;
#else
    return buf[i];
#endif
}
