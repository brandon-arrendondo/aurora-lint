/*
 * Rule: FIO05-C
 * Source: regression (task 407)
 * Status: FAIL - Should trigger FIO05-C violation
 *
 * Companion to tests/pass/cross_function_same_name.c: confirms per-function
 * scoping does not accidentally suppress a genuine reopen violation just
 * because an unrelated function elsewhere in the file uses the same
 * parameter/variable names.
 */

void unrelated_single_open(char *file_name) {
  FILE *fd = fopen(file_name, "w");
  if (fd == NULL) {
    /* Handle error */
  }

  /*... Write to file ...*/

  fclose(fd);
  fd = NULL;
}

void genuinely_reopens(char *file_name) {
  FILE *fd = fopen(file_name, "w");
  if (fd == NULL) {
    /* Handle error */
  }

  /*... Write to file ...*/

  fclose(fd);
  fd = NULL;

  /* Race condition window - attacker can switch file */

  fd = fopen(file_name, "r");
  if (fd == NULL) {
    /* Handle error */
  }

  /*... Read from file ...*/

  fclose(fd);
  fd = NULL;
}
