/*
 * Rule: POS01-C
 * Source: wiki
 * Status: PASS - Should NOT trigger POS01-C violation
 */

void func(char *file_name) {
  struct stat orig_st;
  if (lstat( file_name, &orig_st) != 0) {
    /* handle error */
  }

  if (!S_ISREG( orig_st.st_mode)) {
    /* file is irregular or symlink */
  }

  int fd = open(file_name, O_RDWR);
  if (fd == -1) {
    /* handle error */
  }

  struct stat new_st;
  if (fstat(fd, &new_st) != 0) {
    /* handle error */
  }

  if (orig_st.st_dev != new_st.st_dev ||
      orig_st.st_ino != new_st.st_ino) {
    /* file was tampered with during race window */
  }

  /* ... file is good, operate on fd ... */
}