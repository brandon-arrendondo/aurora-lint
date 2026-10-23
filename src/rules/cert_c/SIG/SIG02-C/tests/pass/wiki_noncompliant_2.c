/*
 * Rule: SIG02-C
 * Source: wiki
 * Status: PASS - Should NOT trigger SIG02-C violation
 *
 * Once a FAIL fixture: CERT's WU-FTPD example, reported because a handler
 * was guessed from its K&R parameter or its name (dologout, lostconn, myoob)
 * and its body made unsafe calls. Unsafe calls inside a handler are SIG30-C's
 * and SIG31-C's. Its signal() calls register handlers, which is not a send.
 * Nothing here sends a signal to the program itself, which is the only form
 * SIG02-C reports.
 */

void dologout(status) {
  if (logged_in) {
    (void) seteuid((uid_t)0);
    logwtmp(ttyline, "", "");
    /* ... */
  }
  _exit(status);
}

static void lostconn(int signo) {
  if (debug)
    syslog(LOG_DEBUG, "lost connection");
  dologout(-1);
}

static void myoob(signo) {
  if (!transflag)
    return;
  /* ... */
  if (strcmp(cp, "ABOR\r\n") == 0) {
    tmpline[0] = '\0';
    reply(426, "Transfer aborted. Data connection closed.");
    reply(226, "Abort successful");
    longjmp(urgcatch, 1);
  }
  /* ... */
}

/* ... */

signal(SIGPIPE, lostconn);
signal(SIGURG, myoob);