/*
 * Rule: FIO05-C
 * Source: regression
 * Status: FAIL - Should trigger FIO05-C violation
 *
 * Companion to tests/pass/reopen_in_opposite_if_arm.c. One handle holds
 * "first.txt", then "second.txt", which is closed and reopened by name on
 * the same path. The second fclose must be filed against "second.txt", the
 * latest open of the handle; filing it by HashMap order under "first.txt"
 * sometimes hid the reopen.
 */

void reused_handle(void) {
  FILE *fd = fopen("first.txt", "w");
  fclose(fd);

  fd = fopen("second.txt", "w");
  /*... Write to file ...*/
  fclose(fd);

  /* Race condition window - attacker can switch file */
  fd = fopen("second.txt", "r");
  fclose(fd);
}
