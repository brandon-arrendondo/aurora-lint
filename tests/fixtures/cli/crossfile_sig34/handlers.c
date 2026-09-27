#include <signal.h>
#include "handlers.h"

void on_int(int sig) {
    (void)sig;
    signal(SIGUSR1, SIG_DFL);
}
