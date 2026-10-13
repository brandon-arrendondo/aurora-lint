/*
 * Rule: DCL40-C
 * Source: testcases
 * Status: PASS - Should NOT trigger DCL40-C violation
 *
 * Declarations that use the C11 _Thread_local keyword declare different
 * objects. None of them is a second, incompatible declaration of another.
 */

#include <threads.h>

static _Thread_local int a;
_Thread_local int d[8];

int use(void) { return a + d[0]; }
