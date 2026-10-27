/*
 * Rule: EXP19-C
 * Source: custom
 * Status: FAIL - Should trigger EXP19-C violation
 * Description: An if whose condition is split across #if arms has no body
 * inside either arm. The statement after the #endif is the body in every
 * configuration, so the finding is reported there, not past the end of the
 * condition's line.
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
