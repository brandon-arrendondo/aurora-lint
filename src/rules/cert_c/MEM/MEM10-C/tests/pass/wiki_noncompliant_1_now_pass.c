/*
 * Rule: MEM10-C
 * Source: wiki
 * Status: FAIL - Should trigger MEM10-C violation
 */

void incr(int *intptr) {
  if (intptr == NULL) {
    /* Handle error */
  }
  (*intptr)++;
}