/*
 * Rule: DCL36-C
 * Source: testcases
 * Status: PASS - Should NOT trigger DCL36-C violation
 *
 * Each object is declared once with the C11 _Thread_local keyword, in
 * either order with its other storage class. No identifier is declared with
 * two linkages, and the type keyword is not an identifier.
 */

#include <threads.h>

static _Thread_local int a;
_Thread_local static int b;
extern _Thread_local int c;
_Thread_local int d[8];
/* _Thread_local in a comment, and in a string, is left alone. */
const char *const spelling = "_Thread_local";

int use(void) { return a + b + c + d[0] + spelling[0]; }
