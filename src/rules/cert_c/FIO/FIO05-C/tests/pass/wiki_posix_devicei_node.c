/*
 * Rule: FIO05-C
 * Source: wiki
 * Status: PASS - Should NOT trigger FIO05-C violation
 */

void posix_device_inode_example(char *file_name) {
  struct stat orig_st;
  struct stat new_st;

  int fd = open(file_name, O_WRONLY);
  if (fd == -1) {
    /* Handle error */
  }

  /*... Write to file ...*/

  if (fstat(fd, &orig_st) == -1) {
    /* Handle error */
  }
  close(fd);
  fd = -1;

  /* ... */

  fd = open(file_name, O_RDONLY);
  if (fd == -1) {
    /* Handle error */
  }

  if (fstat(fd, &new_st) == -1) {
    /* Handle error */
  }

  if ((orig_st.st_dev != new_st.st_dev) ||
      (orig_st.st_ino != new_st.st_ino)) {
    /* File was tampered with! */
  }

  /*... Read from file ...*/

  close(fd);
  fd = -1;
}
