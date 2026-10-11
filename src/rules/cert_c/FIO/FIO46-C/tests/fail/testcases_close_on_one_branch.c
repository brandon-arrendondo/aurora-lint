/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - on the path through the close, the write uses a closed
 * stream
 */

#include <stdio.h>

void save(FILE *fp, int bad) {
  if (bad) {
    fclose(fp);
  }
  fprintf(fp, "ok\n");
}
