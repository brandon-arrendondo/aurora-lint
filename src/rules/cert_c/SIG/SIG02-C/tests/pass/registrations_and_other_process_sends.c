/*
 * Rule: SIG02-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger SIG02-C violation
 *
 * Shapes that once read as signals used for normal functionality and are
 * not a send to the program itself: ignoring SIGPIPE (no handler is
 * installed), SIGIOT (not SIGIO), a kill() to a child process, restoring a
 * saved disposition, a handler named myoob, and a kill() through a function
 * pointer parameter.
 */
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

static struct sigaction saved;

static void myoob(int sig)
{
    (void)sig;
}

void setup(pid_t child)
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGIOT, SIG_DFL);
    signal(SIGURG, myoob);
    kill(child, SIGUSR1);
    sigaction(SIGALRM, &saved, NULL);
}

int send_through(int (*kill)(pid_t, int))
{
    return kill(getpid(), SIGUSR1);
}
