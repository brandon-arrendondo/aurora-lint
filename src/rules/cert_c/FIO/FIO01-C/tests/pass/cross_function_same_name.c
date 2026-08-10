/*
 * Rule: FIO01-C
 * Source: regression (task 406)
 * Status: PASS - Should NOT trigger FIO01-C violation
 *
 * Two unrelated functions each declare a local variable named
 * "file_name" (and "f_ptr"). Function A only opens+closes its own
 * file_name by descriptor; function B only removes its own,
 * unrelated file_name. Neither function on its own performs a
 * TOCTOU-unsafe open-then-name-operate sequence. Prior to the
 * per-function scoping fix, the two same-named locals' operation
 * timelines were merged into one global bucket, causing a false
 * positive here.
 */

void open_only(void) {
  char *file_name = "a.txt";
  FILE *f_ptr;

  f_ptr = fopen(file_name, "w");
  if (f_ptr == NULL) {
    /* Handle error */
  }

  if (fclose(f_ptr) != 0) {
    /* Handle error */
  }
}

void remove_only(void) {
  char *file_name = "b.txt";

  if (remove(file_name) != 0) {
    /* Handle error */
  }
}
