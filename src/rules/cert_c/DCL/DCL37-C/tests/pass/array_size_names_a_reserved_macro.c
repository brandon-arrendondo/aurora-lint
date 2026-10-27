/*
 * Rule: DCL37-C
 * Status: PASS - an array's size is not part of the name being declared, so a
 * reserved macro used as the size declares nothing.
 */

#include <stdio.h>

char line[BUFSIZ];

struct record {
  char name[_POSIX_PATH_MAX];
};

void fill(void) {
  char scratch[__SIZEOF_POINTER__ * 8];
  int (*rows)[_POSIX_ARG_MAX];
  (void)scratch;
  (void)rows;
}
