/*
 * Rule: DCL37-C
 * Status: FAIL - the compiler defines __STRICT_ANSI__ under -ansi or -std=c99;
 * a program defining it is not requesting a feature.
 * Expect: count=1
 */

#define __STRICT_ANSI__ 1 /* Expect: here */

int main(void) { return 0; }
