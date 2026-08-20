/*
 * Rule: POS01-C
 * Source: wiki
 * Status: FAIL - Should trigger POS01-C violation
 */

void func(char *file_name, char *userbuf, unsigned int userlen) {
  int fd = open(file_name, O_RDWR);
  if (fd == -1) {
     /* handle error */
  }
  write(fd, userbuf, userlen);
}