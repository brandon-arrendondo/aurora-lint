/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - puts() writes stdout, which has been closed (C11 7.21.7.9)
 */

#include <stdio.h>

void report(void) {
  fclose(stdout);
  puts("done");
}
