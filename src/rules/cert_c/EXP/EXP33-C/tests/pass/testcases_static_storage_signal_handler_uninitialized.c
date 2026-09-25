/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation
 */

/*
 * Rule: EXP33-C - Do not read uninitialized memory
 * Status: PASS
 * Reason: The variable is a file-scope `static int` with no initializer. Objects with static or thread
 *         storage duration are zero-initialized when they have no
 *         initializer (C11 6.7.9p10), so every read below sees a determinate
 *         value. This fixture used to assert the opposite.
 */

#include <stdio.h>
#include <signal.h>

static int signal_count;  /* Uninitialized global */

/* Well-defined: Signal handler uses uninitialized data */
void signal_handler(int sig) {
    signal_count++;  /* Increments uninitialized value */
    printf("Signal received %d times\n", signal_count);
}

int main(void) {
    signal(SIGINT, signal_handler);
    raise(SIGINT);  /* Trigger signal handler */
    return 0;
}