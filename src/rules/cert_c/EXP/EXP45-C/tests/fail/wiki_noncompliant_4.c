/*
 * Rule: EXP45-C
 * Source: wiki
 * Status: FAIL - Should trigger EXP45-C violation
 */

while (ch = '\t' || ch == ' ' || ch == '\n') {
  /* ... */
}