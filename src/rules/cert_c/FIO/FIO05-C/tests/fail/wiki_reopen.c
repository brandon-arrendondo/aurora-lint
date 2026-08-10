/*
 * Rule: FIO05-C
 * Source: wiki
 * Status: FAIL - Should trigger FIO05-C violation
 */

void reopen_example(char *file_name) {
  FILE *fd = fopen(file_name, "w");
  if (fd == NULL) {
    /* Handle error */
  }

  /*... Write to file ...*/

  fclose(fd);
  fd = NULL;

  /*
   * A race condition here allows for an attacker
   * to switch out the file for another.
   */

  /* ... */

  fd = fopen(file_name, "r");
  if (fd == NULL) {
    /* Handle error */
  }

  /*... Read from file ...*/

  fclose(fd);
  fd = NULL;
}
