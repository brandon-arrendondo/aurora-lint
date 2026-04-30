/*
 * Rule: DCL31-C
 * Source: wiki
 * Status: FAIL - Should trigger DCL31-C violation
 */

/* file_a.c source file */
int func(int one, int two, int three){
  custom_print("%d %d %d", one, two, three);
  return 1;
}
