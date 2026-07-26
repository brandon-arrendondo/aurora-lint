/*
 * Rule: FIO21-C
 * Source: wiki
 * Status: FAIL - Should trigger FIO21-C violation
 */

#include <stdio.h>
 
void func(void) {
  char file_name[L_tmpnam];
  int fd;

  if (!(tmpnam(file_name))) {
    /* Handle error */
  }

  /* A TOCTOU race condition exists here */

  fd = open(file_name, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC,
            0600);
  if (fd < 0) {
     /* Handle error */
  }
}