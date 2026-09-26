/*
 * Rule: PRE32-C
 * Source: testcases
 * Status: PASS - Should NOT trigger PRE32-C violation
 *
 * `LOG_LINE` is spelled like a macro but is a declared function that no
 * branch defines as a macro. A directive inside the arguments of an
 * ordinary function call is well-defined, so this is not a PRE32-C case.
 */

int LOG_LINE(const char *msg, int level);

int report(void)
{
    return LOG_LINE("ready",
#ifdef VERBOSE
                    2
#else
                    1
#endif
    );
}
