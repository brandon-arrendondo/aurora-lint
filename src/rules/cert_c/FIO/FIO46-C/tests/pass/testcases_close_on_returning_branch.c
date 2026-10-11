/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - the close is on a branch that returns, so no path from it
 * reaches the later write
 */

#include <stdio.h>

int save(FILE *fp, int bad) {
  if (bad) {
    fclose(fp);
    return -1;
  }
  fprintf(fp, "ok\n");
  return fclose(fp);
}
