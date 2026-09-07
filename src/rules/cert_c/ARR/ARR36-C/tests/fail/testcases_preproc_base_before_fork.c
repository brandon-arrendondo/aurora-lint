/*
 * Rule: ARR36-C
 * Source: testcases
 * Status: FAIL - Should trigger ARR36-C violation
 */

/*
 * Rule: ARR36-C - Do not subtract or compare two pointers that do not refer to
 *       the same array
 * Status: FAIL
 * Reason: A base recorded ABOVE the #if is in no arm at all, so it coexists
 *         with every arm and still answers inside one. The counterpart to
 *         pass/testcases_preproc_exclusive_arms.c, which suppresses only the
 *         records the preprocessor puts in a branch the reader is not in.
 */

#include <stddef.h>

ptrdiff_t span(void)
{
    char first[32];
    char second[32];
    char *pos = first;

#ifdef CONFIG_A
    char *end = second;

    return end - pos;  /* VIOLATION: 'second' against 'first' */
#else
    return 0;
#endif
}

int main(void)
{
    return (int) span();
}
