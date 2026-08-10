/*
 * Rule: FIO05-C
 * Source: wiki
 * Status: PASS - Should NOT trigger FIO05-C violation
 */

void posix_owner_example(char *file_name) {
  struct stat st;

  int fd = open(file_name, O_RDONLY);
  if (fd == -1) {
    /* Handle error */
  }

  if ((fstat(fd, &st) == -1) ||
     (st.st_uid != getuid()) ||
     (st.st_gid != getgid())) {
    /* File does not belong to user */
  }

  /*... Read from file ...*/

  close(fd);
  fd = -1;
}
