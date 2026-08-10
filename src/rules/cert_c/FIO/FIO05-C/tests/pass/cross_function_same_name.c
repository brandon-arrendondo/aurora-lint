/*
 * Rule: FIO05-C
 * Source: regression (task 407)
 * Status: PASS - Should NOT trigger FIO05-C violation
 *
 * Two unrelated functions each open and close a file exactly once using a
 * parameter/variable named "file_name" and "fd". Neither function reopens
 * anything on its own. Before task 407's fix, FIO05-C analyzed the whole
 * translation_unit as a single merged timeline keyed by filename text, so
 * these two independent single-open sequences (both keyed under the literal
 * text "file_name") looked like one Open -> Close -> Open reopen sequence
 * and produced a false positive. With per-function scoping (a fresh
 * file_operations map per function_definition), each function's single
 * open/close pair is analyzed in isolation and no reopen pattern exists.
 */

void first_task(char *file_name) {
  FILE *fd = fopen(file_name, "w");
  if (fd == NULL) {
    /* Handle error */
  }

  /*... Write to file ...*/

  fclose(fd);
  fd = NULL;
}

void second_task(char *file_name) {
  FILE *fd = fopen(file_name, "w");
  if (fd == NULL) {
    /* Handle error */
  }

  /*... Write to file ...*/

  fclose(fd);
  fd = NULL;
}
