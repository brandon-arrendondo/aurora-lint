/*
 * Rule: MSC12-C
 * Source: custom
 * Status: PASS - Should NOT trigger MSC12-C violation
 * Description: The `;` after `}` ends the declaration of a local array
 * whose initializer list holds an #ifdef. Unrepaired, the grammar has no
 * production for a conditional inside an initializer list, the declaration
 * was lost to the parse error, and the `};` read as a stray empty statement.
 */

int first_enabled(int i)
{
    int enabled[] = {
#ifdef WITH_FEATURE_A
        7,
#endif
        3
    };
    return enabled[i];
}
