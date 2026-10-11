#include <signal.h>

void handler(int signum) {
#if !defined(_WIN32)
  if (signal(signum, SIG_DFL) == SIG_ERR) {
    /* Handle error */
  }
#endif
  /* EX1 covers only the handler's own signal. */
  (void)signal(SIGUSR2, SIG_IGN);
}

void func(void) {
  if (signal(SIGUSR1, handler) == SIG_ERR) {
    /* Handle error */
  }
}
