/*
 * Rule: SIG02-C
 * Source: synthetic
 * Status: FAIL - Should trigger SIG02-C violation
 *
 * The program sends itself an ordinary-work signal three ways: raise(),
 * kill() aimed at getpid(), and pthread_kill() to one of its own threads.
 */
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

void wake_self(void)
{
    raise(SIGUSR1);
}

void wake_own_process(void)
{
    kill(getpid(), SIGUSR2);
}

void wake_worker(pthread_t worker)
{
    pthread_kill(worker, SIGALRM);
}
