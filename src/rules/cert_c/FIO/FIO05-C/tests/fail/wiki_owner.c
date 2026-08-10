/*
 * Rule: FIO05-C
 * Source: wiki
 * Status: FAIL - Should trigger FIO05-C violation
 */

void owner_example(char *file_name) {
  FILE *fd;

  fd = fopen(file_name, "r+");
  if (fd == NULL) {
    /* Handle error */
  }

  /* Read user's file */

  fclose(fd);
  fd = NULL;
}
