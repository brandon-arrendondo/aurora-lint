/*
 * Rule: PRE00-C
 * Source: wiki
 * Status: FAIL - Should trigger PRE00-C violation
 */

size_t count = 0;

#define EXEC_BUMP(func) (func(), ++count)

void g(void) {
  printf("Called g, count = %zu.\n", count);
}

void aFunc(void) {
  size_t count = 0;
  while (count++ < 10) {
    EXEC_BUMP(g);
  }
}