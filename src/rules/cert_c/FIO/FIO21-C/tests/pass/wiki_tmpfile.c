/*
 * Rule: FIO21-C
 * Source: wiki
 * Status: PASS under the default preset; VIOLATION under strict
 * Expect: default=clean strict=violation
 *
 * The default preset assumes POSIX, which removes the file tmpfile() creates
 * when the stream is closed or the process ends, so it does not report the
 * call (fio21_tmpfile_exempt_under_posix). The strict policy reports it as
 * CERT's page is written.
 */

#include <stdio.h>
 
void func(void) {
  FILE *fp = tmpfile();
  if (fp == NULL) {
    /* Handle error */
  }
}