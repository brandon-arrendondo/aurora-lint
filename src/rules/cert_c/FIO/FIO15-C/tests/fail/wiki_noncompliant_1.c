/*
 * Rule: FIO15-C
 * Source: wiki, adapted from CERT (not verbatim)
 * Adapted: CERT names the file with a variable (file_name); this copy uses
 * the literal "/tmp/myfile", which the rule detects by its path. CERT's
 * example as written is expected_fail/wiki_noncompliant_1_verbatim.c.
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