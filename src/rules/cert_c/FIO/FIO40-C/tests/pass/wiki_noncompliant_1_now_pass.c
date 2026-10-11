/*
 * Rule: FIO40-C
 * Source: wiki
 * Status: PASS - This is CERT's noncompliant example, but nothing reads
 * buf after the failed call. The rule reports a read of the array on a
 * path where fgets() failed, before anything writes it; CERT's EX1 (no
 * reset is needed when the buffer is not used afterwards) follows from
 * that form, and it covers this example's literal shape.
 */

#include <stdio.h>
 
enum { BUFFER_SIZE = 1024 };
void func(FILE *file) {
  char buf[BUFFER_SIZE];

  if (fgets(buf, sizeof(buf), file) == NULL) {
    /* Set error flag and continue */
  }
}
