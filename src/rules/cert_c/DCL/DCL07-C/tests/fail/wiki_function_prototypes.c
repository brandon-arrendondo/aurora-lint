/*
 * Rule: DCL07-C
 * Source: wiki
 * Status: FAIL - Should trigger DCL07-C violation
 */

/* file_a.c source file */
int func(int one, int two, int three){
  printf("%d %d %d", one, two, three);
  return 1;
}