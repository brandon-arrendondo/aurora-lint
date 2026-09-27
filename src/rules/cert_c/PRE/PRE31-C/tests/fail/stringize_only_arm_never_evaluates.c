/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: in the second arm x is only a # operand, so it is stringized and
 * never evaluated.
 */

#include <stdio.h>

#ifdef TRACE_VALUES
#define TRACE(x) printf("%d\n", (x))
#else
#define TRACE(x) puts(#x)
#endif

void t(int i) {
    TRACE(i++);  // VIOLATION
}
