/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - the close is followed by exit(), which does not return
 */

#include <stdio.h>
#include <stdlib.h>

void save(FILE *fp, int bad) {
  if (bad) {
    fclose(fp);
    exit(EXIT_FAILURE);
  }
  fputs("ok\n", fp);
  fclose(fp);
}
