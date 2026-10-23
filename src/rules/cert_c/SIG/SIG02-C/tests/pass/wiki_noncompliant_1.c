/*
 * Rule: SIG02-C
 * Source: wiki
 * Status: PASS - Should NOT trigger SIG02-C violation
 *
 * Once a FAIL fixture: CERT's first noncompliant example. Its text speaks of
 * one thread waking another, but kill(THR2_PID, ...) is process-directed: it
 * signals another process, not a thread of this one (pthread_kill() would).
 * SIG02-C reports only the program signaling its own process or threads.
 */

/* THREAD 1 */
int do_work(void) {
  /* ... */
  kill(THR2_PID, SIGUSR1);
}

/* THREAD 2 */
volatile sig_atomic_t flag;

void sigusr1_handler(int signum) {
  flag = 1;
}

int wait_and_work(void) {
  flag = 0;
  while (!flag) {}
  /* ... */
}