/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - getchar() and scanf() read stdin, which has been closed
 * (C11 7.21.7.6, 7.21.6.4)
 */

#include <stdio.h>

int read_after_close(void) {
  int n = 0;
  fclose(stdin);
  if (scanf("%d", &n) != 1) {
    return getchar();
  }
  return n;
}
