/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - the stream is assigned NULL after its close, so the later
 * test reads a determinate value and closes only an open stream
 */

#include <stdio.h>

void finish(FILE *fp, int bad) {
  if (bad) {
    fclose(fp);
    fp = NULL;
  }
  if (fp != NULL) {
    fclose(fp);
  }
}
