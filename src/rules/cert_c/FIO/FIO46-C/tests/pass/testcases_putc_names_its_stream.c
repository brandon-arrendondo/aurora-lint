/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - putc() writes the stream it is given, here stderr, not the
 * closed stdout (C11 7.21.7.7)
 */

#include <stdio.h>

void report(void) {
  fclose(stdout);
  putc('!', stderr);
  fputs("stdout closed\n", stderr);
}
