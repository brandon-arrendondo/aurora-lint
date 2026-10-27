/*
 * Rule: EXP39-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP39-C violation
 *
 * Stepping from one struct member's address to the next assumes a layout,
 * but this rule is about the type of the object an lvalue accesses: the
 * int read here is an int.
 */

struct pair {
  int a;
  int b;
};

int second(void) {
  struct pair s = {1, 2};
  int *ip = &s.a;
  return *(int *)(ip + 1);
}
