/*
 * Rule: EXP19-C
 * Source: custom
 * Status: PASS - Should NOT trigger EXP19-C violation
 * Description: Two ifs in a row, each with its condition split across
 * #if arms and a braced body, inside enclosing #ifdef blocks. Every
 * configuration's body is braced, and the statement after the enclosing
 * #endif is no if's body, so nothing is reported.
 */

int two_enclosing_arms(int a, int b)
{
#ifdef FEATURE
#ifdef PLATFORM
#ifdef FAST_A
    if (a)
#else
    if (b)
#endif
    {
        b++;
    }
#ifdef FAST_B
    if (a)
#else
    if (b)
#endif
    {
        b++;
    }
#endif
#endif
    return 0;
}
