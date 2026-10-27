/*
 * Rule: EXP19-C
 * Source: custom
 * Status: FAIL - Should trigger EXP19-C violation
 * Description: Two ifs in a row, each with its condition split across
 * #if arms, inside one or more enclosing #ifdef blocks. Each if's body is
 * the statement after its own #endif, reported there once; the statement
 * after the enclosing #endif is no if's body in any configuration.
 * Expect: count=4
 */

int one_enclosing_arm(int a, int b)
{
#ifdef FEATURE
#ifdef FAST_A
    if (a)
#else
    if (b)
#endif
        b++; /* Expect: here */
#ifdef FAST_B
    if (a)
#else
    if (b)
#endif
        b++; /* Expect: here */
#endif
    return 0;
}

int two_enclosing_arms(int a, int b)
{
#ifdef FEATURE
#ifdef PLATFORM
#ifdef FAST_A
    if (a)
#else
    if (b)
#endif
        b++; /* Expect: here */
#ifdef FAST_B
    if (a)
#else
    if (b)
#endif
        b++; /* Expect: here */
#endif
#endif
    return 0;
}
