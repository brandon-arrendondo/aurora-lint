/*
 * Rule: SIG02-C
 * Source: synthetic
 * Status: FAIL - Should trigger SIG02-C violation
 * Expect: count=3
 *
 * The program sends itself signals that usually report an abnormal event.
 * CERT names no set of signals that carry normal functionality, so a send
 * to the program's own process is reported whatever the signal.
 */
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

void stop_self(void)
{
    raise(SIGTERM); /* Expect: here */
}

void abort_self(void)
{
    raise(SIGABRT); /* Expect: here */
}

void interrupt_own_process(void)
{
    kill(getpid(), SIGINT); /* Expect: here */
}
