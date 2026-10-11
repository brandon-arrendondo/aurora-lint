/*
 * Rule: SIG34-C
 * Source: wiki
 * Status: FAIL - EX1 holds only for implementations with persistent
 * handlers, and the `#if !defined(_WIN32)` guard names a platform, not a
 * persistent one (C11 7.14.1.1p3 and POSIX leave the reset
 * implementation-defined). Declaring signal_handlers_persistent makes it
 * compliant; tests/cli_integration.rs checks that.
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