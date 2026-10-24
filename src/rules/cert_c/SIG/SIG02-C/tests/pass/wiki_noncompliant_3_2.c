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

void dologout(status) {
 /*
  * Prevent reception of SIGURG from resulting in a resumption
  * back to the main program loop.
  */ 
  transflag = 0;
  if (logged_in) {
    (void) seteuid((uid_t)0);
    logwtmp(ttyline, "", "");
    /* ... */
  }
  _exit(status);
}