/*
 * Rule: MSC15-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC15-C violation
 */

#include <assert.h>
#include <limits.h>
#include <stdio.h>
 
int foo(int a) {
  assert(a + 100 > a);
  printf("%d %d\n", a + 100, a);
  return a;
}

int main(void) {
  foo(100);
  foo(INT_MAX);
  return 0;
}