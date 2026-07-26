/*
 * Rule: EXP45-C
 * Source: wiki
 * Status: FAIL - Should trigger EXP45-C violation
 */

while ('\t' = ch || ' ' == ch || '\n' == ch) {
  /* ... */
}