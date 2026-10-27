/*
 * Rule: DCL37-C
 * Status: FAIL - every source documents its feature-test macros as
 * object-like. Defining a listed name as a function-like macro is not what any
 * of them asks the program to do, so the exemption does not cover it.
 * Expect: count=2
 */

#define _GNU_SOURCE() 1 /* Expect: here */
#define _XOPEN_SOURCE(x) x /* Expect: here */

int main(void) { return 0; }
