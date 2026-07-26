/*
 * Rule: SIG34-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#include <signal.h>
 
void handler(int signum) {
#if !defined(_WIN32)
  if (signal(signum, SIG_DFL) == SIG_ERR) {
    /* Handle error */
  }
#endif
  /* Handle signal */
}
 
void func(void) {
  if (signal(SIGUSR1, handler) == SIG_ERR) {
    /* Handle error */
  }
}