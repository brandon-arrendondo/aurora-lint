/*
 * Rule: POS35-C
 * Source: wiki
 * Status: FAIL - Should trigger POS35-C violation
 */

void func(char *filename, char *userbuf, unsigned int userlen) {
  struct stat lstat_info;
  int fd;
  /* ... */
  if (lstat(filename, &lstat_info) == -1) {
    /* Handle error */
  }

  if (!S_ISLNK(lstat_info.st_mode)) {
     fd = open(filename, O_RDWR);
     if (fd == -1) {
         /* Handle error */
     }
  }
  if (write(fd, userbuf, userlen) < userlen) {
    /* Handle error */
  }
}