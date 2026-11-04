/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - Either preprocessor arm's declaration of the index may be the one built
 * Expect: count=2
 *
 * Each function declares its index once in each arm of a conditional,
 * one arm reading it from outside and the other giving it an in-bounds
 * constant. The build compiles one arm, and the unchecked one is a
 * possible build, whichever arm comes first.
 */

int read_untrusted(void);

int buf[3];

int element_untrusted_arm_first(void)
{
#if defined(BIG)
    int i = read_untrusted();
#else
    int i = 2;
#endif
    return buf[i]; /* Expect: here */
}

int element_untrusted_arm_second(void)
{
#ifdef SMALL
    int i = 2;
#else
    int i = read_untrusted();
#endif
    return buf[i]; /* Expect: here */
}
