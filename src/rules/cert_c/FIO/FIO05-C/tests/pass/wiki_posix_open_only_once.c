/*
 * Rule: FIO05-C
 * Source: wiki
 * Status: PASS - Should NOT trigger FIO05-C violation
 */

void open_only_once_example(char *file_name) {
  FILE *fd;

  fd = fopen(file_name, "w+");
  if (fd == NULL) {
    /* Handle error */
  }

  /*... Write to file ...*/

  /* Go to beginning of file */
  fseek(fd, 0, SEEK_SET);

  /*... Read from file ...*/

  fclose(fd);
  fd = NULL;
}
