/*
 * Rule: DCL20-C
 * Source: aurora-lint
 * Status: FAIL - the macro expands to the type it is given, not a statement
 * Expect: count=1
 */

#define RESULT(t) t

RESULT(int) compute(); /* Expect: here */
