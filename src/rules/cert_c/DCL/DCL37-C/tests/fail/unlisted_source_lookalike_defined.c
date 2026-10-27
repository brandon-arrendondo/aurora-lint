/*
 * Rule: DCL37-C
 * Status: FAIL - shaped like a feature-test macro, but no standard or
 * implementation documents it, so it is a reserved identifier.
 * Expect: count=1
 */

#define _MY_SOURCE 1 /* Expect: here */

int main(void) { return 0; }
