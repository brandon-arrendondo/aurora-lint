/*
 * Rule: SIG02-C
 * Source: wiki
 * Status: PASS - Should NOT trigger SIG02-C violation
 *
 * Once a FAIL fixture: CERT's WU-FTPD example, reported because a handler
 * was guessed from its K&R parameter or its name (dologout, lostconn, myoob)
 * and its body made unsafe calls. Unsafe calls inside a handler are SIG30-C's
 * and SIG31-C's. Nothing here sends a signal to the program itself, which is
 * the only form SIG02-C reports.
 */

volatile sig_atomic_t xfer_aborted = 0;

static void myoob(signo) {
  /* ... */
  if (strcmp(cp, "ABOR\r\n") == 0) {
    xfer_aborted = 1;
  }
  /* ... */
}