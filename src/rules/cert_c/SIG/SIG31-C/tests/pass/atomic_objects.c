/*
 * Rule: SIG31-C
 * Source: aurora-lint
 * Status: PASS - _Atomic-qualified objects, an atomic pointer and a <stdatomic.h> type are atomic objects
 */

#include <signal.h>
#include <stdatomic.h>

static _Atomic int pending;
static int target;
static int *_Atomic where = &target;
static atomic_flag busy = ATOMIC_FLAG_INIT;

static void on_usr1(int sig) {
    (void)sig;
    pending = 1;
    where = 0;
    atomic_flag_clear(&busy);
}

int main(void) {
    if (signal(SIGUSR1, on_usr1) == SIG_ERR) {
        return 1;
    }
    return pending;
}
