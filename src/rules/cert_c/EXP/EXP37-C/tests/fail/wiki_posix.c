/*
 * Rule: EXP37-C
 * Source: wiki
 * Status: FAIL - Should trigger EXP37-C violation
 *
 * Noncompliant: open() is called without the mode_t argument
 * required whenever O_CREAT is specified in oflag.
 */

#include <fcntl.h>

void func(const char *ms) {
  int fd;
  fd = open(ms, O_CREAT | O_EXCL | O_WRONLY | O_TRUNC);
  if (fd == -1) {
    /* Handle error */
  }
}