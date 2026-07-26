/*
 * Rule: DCL01-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#define SWAP(type, a, b) do { type tmp = a; a = b; b = tmp; } while(0)
 
void func(void) {
  int tmp = 100;
  int a = 10, b = 20;
  SWAP(int, a, b); /* Hidden redeclaration of tmp is acceptable */
  SWAP(int, tmp, b); /* NONCOMPLIANT: Hidden redeclaration of tmp clashes with argument */
}