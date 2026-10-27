/*
 * Rule: EXP19-C
 * Source: custom
 * Status: FAIL - Should trigger EXP19-C violation
 * Description: An if whose condition is split across #if arms has no body
 * inside any arm. The statement after the #endif is the body in every
 * configuration, so it is reported there, once: every arm's if names the
 * same statement, and one pair of braces fixes them all. No arm's if is
 * the body of another's.
 * Expect: count=2
 */

int split_condition(int a, int b)
{
#ifdef FEATURE_A
    if (a && b)
#else
    if (a)
#endif
        return 1; /* Expect: here */
    return 0;
}

int split_three_ways(int a, int b)
{
#ifdef FEATURE_A
    if (a && b)
#elif defined(FEATURE_B)
    if (b)
#else
    if (a)
#endif
        return 1; /* Expect: here */
    return 0;
}
