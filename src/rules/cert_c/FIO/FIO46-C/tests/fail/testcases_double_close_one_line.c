/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - the second fclose on the line closes the stream the first
 * one closed
 */

#include <stdio.h>

void finish(FILE *fp) {
  fclose(fp); fclose(fp);
}
