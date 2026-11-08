/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A macro redefined between chains leaves the arm array in scope
 *
 * The local of 8 is compiled with the access, which fits it.
 */

int buf[4];
int c;

int element(void)
{
#define A 1
#if A
    int buf[8];
#endif
#undef A
#define A 0
#if A
    return 0;
#else
    return buf[7];
#endif
}
