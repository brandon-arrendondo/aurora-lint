/*
 * Rule: SIG02-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger SIG02-C violation
 *
 * The file defines its own raise(), an event-queue function that shares
 * the library's name; the call reaches it, not <signal.h>'s.
 */
#define SIGUSR1 10

static int pending[32];

int raise(int event)
{
    pending[event] = 1;
    return 0;
}

void post(void)
{
    raise(SIGUSR1);
}
