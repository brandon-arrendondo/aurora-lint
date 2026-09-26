/*
 * Rule: MSC37-C
 * Source: wiki
 * Status: PASS - Compliant solution
 *
 * Settings: stdlib_noreturn=true
 * The library contract that abort/exit never return is held on under every
 * preset: it is not what this fixture tests (the strict preset's
 * freestanding environment withdraws it; see
 * src/rules/cert_c/MEM/MEM30-C/tests/pass/stdlib_exit_branch_needs_stdlib_noreturn.c).
 */

#include <stdio.h>
#include <stdlib.h>
 
_Noreturn void unreachable(const char *msg) {
  printf("Unreachable code reached: %s\n", msg);
  exit(1);
}

enum E {
  One,
  Two,
  Three
};
 
int f(enum E e) {
  switch (e) {
  case One: return 1;
  case Two: return 2;
  case Three: return 3;
  }
  unreachable("Can never get here");
}