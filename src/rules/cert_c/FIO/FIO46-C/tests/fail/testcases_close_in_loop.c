/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - the second iteration writes the stream the first one closed
 */

#include <stdio.h>

void dump(FILE *fp, int n) {
  for (int i = 0; i < n; i++) {
    fprintf(fp, "%d\n", i);
    fclose(fp);
  }
}
