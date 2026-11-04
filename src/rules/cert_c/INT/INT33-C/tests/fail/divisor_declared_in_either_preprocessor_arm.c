/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - Either preprocessor arm's declaration of the divisor may be the one built
 * Expect: count=2
 *
 * Each function declares its divisor once in each arm of a conditional,
 * one arm reading it from outside and the other giving it a nonzero
 * constant. The build compiles one arm, and the unchecked one is a
 * possible build, whichever arm comes first.
 */

int read_untrusted(void);

int ratio_untrusted_arm_first(void)
{
#ifdef FROM_INPUT
    int x = read_untrusted();
#else
    int x = 4;
#endif
    return 10 / x; /* Expect: here */
}

int ratio_untrusted_arm_second(void)
{
#if defined(FIXED)
    int x = 4;
#else
    int x = read_untrusted();
#endif
    return 10 / x; /* Expect: here */
}
