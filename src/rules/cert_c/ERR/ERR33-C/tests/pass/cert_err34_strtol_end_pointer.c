/*
 * Rule: ERR33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ERR33-C violation
 */

/*
 * Rule: ERR33-C - Detect and handle standard library errors
 * Status: PASS
 * Reason: CERT ERR34-C compliant strtol: the end pointer, named 'end', and errno are both read in the conditions that follow.
 */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
 
void func(const char *buff) {
  char *end;
  int si;

  errno = 0;

  const long sl = strtol(buff, &end, 10);

  if (end == buff) {
    (void) fprintf(stderr, "%s: not a decimal number\n", buff);
  } else if ('\0' != *end) {
    (void) fprintf(stderr, "%s: extra characters at end of input: %s\n", buff, end);
  } else if ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno) {
    (void) fprintf(stderr, "%s out of range of type long\n", buff);
  } else if (sl > INT_MAX) {
    (void) fprintf(stderr, "%ld greater than INT_MAX\n", sl);
  } else if (sl < INT_MIN) {
    (void) fprintf(stderr, "%ld less than INT_MIN\n", sl);
  } else {
    si = (int)sl;

    /* Process si */
  }
}