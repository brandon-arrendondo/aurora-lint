/*
 * Rule: ENV03-C
 * Source: wiki
 * Status: FAIL - Should trigger ENV03-C violation
 */

if (system("/bin/ls dir.`date +%Y%m%d`") == -1) {
  /* Handle error */
}