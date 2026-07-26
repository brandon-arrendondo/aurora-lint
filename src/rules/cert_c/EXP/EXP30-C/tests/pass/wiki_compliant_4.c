/*
 * Rule: EXP30-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

extern void func(int i, int j);
 
void f(int i) {
  i++;
  func(i, i);
}