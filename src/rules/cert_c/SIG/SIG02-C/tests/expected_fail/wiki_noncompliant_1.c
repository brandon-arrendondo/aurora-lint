/*
 * Rule: SIG02-C
 * Source: wiki
 * Status: EXPECTED_FAIL - an own-process kill() whose pid is not resolved
 *
 * CERT's first noncompliant example: THR2_PID names thread 2 of this same
 * program, so kill(THR2_PID, SIGUSR1) is the program signaling itself, the
 * form SIG02-C reports. The rule credits kill() as own-process only when its
 * pid is a call of the library's getpid(); THR2_PID is a name nothing here
 * declares, so the send is not recognized. A known miss, not a pass.
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