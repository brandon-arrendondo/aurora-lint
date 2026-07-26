/*
 * Rule: EXP30-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#include <stdio.h>

void func(int i, int *b) {
  int a;
  ++i;
  a = i + b[i];
  printf("%d, %d", a, i);
}