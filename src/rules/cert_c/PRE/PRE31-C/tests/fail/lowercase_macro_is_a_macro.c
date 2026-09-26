/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: FAIL - Should trigger PRE31-C violation
 *
 * Whether a call is a macro invocation comes from the macro's definition,
 * not its spelling: `mymax` is lowercase but is a function-like macro that
 * evaluates each argument twice.
 */

#define mymax(a, b) ((a) > (b) ? (a) : (b))

int next_larger(int i, int limit)
{
    return mymax(i++, limit);  /* VIOLATION: i++ may run twice */
}
