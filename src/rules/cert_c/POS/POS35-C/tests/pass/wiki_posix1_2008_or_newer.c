/*
 * Rule: POS35-C
 * Source: wiki
 * Status: PASS - Should NOT trigger POS35-C violation
 */

void func(char *filename, char *userbuf, unsigned int userlen) {
  int fd = open(filename, O_RDWR|O_NOFOLLOW);
  if (fd == -1) {
    /* Handle error */
  }
  if (write(fd, userbuf, userlen) < userlen) {
    /* Handle error */
  }
}