/*
 * Rule: MSC37-C
 * Source: wiki
 * Status: PASS - Compliant solution
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