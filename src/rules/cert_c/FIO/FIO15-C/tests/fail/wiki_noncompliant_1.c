/*
 * Rule: FIO15-C
 * Source: wiki, adapted from CERT (not verbatim)
 * Adapted: CERT names the file with a variable (file_name); this copy uses
 * the literal "/tmp/myfile", which the rule detects by its path. CERT's own
 * form is out of reach by ruling: FIO15-C is ruled unenforceable, because
 * whether a directory is secure is a property of the running system, not
 * of the source, so no fixture asserts that it should be reported.
 * Status: FAIL - Should trigger FIO15-C violation
 */

#include <stdio.h>
#include <stdlib.h>

void process_file(void) {
  FILE *fp;

  // VIOLATION: Using /tmp directly without security checks
  fp = fopen("/tmp/myfile", "w");
  if (fp == NULL) {
    return;
  }

  fprintf(fp, "data");

  if (fclose(fp) != 0) {
    return;
  }

  if (remove("/tmp/myfile") != 0) {
    return;
  }
}