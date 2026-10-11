/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - on the path through the first close the stream is closed
 * again
 */

#include <stdio.h>

void finish(FILE *fp, int bad) {
  if (bad) {
    fclose(fp);
  }
  fclose(fp);
}
