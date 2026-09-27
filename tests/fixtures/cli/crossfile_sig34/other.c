#include <signal.h>

/* Shares its name with the handler main.c registers, but is this file's
 * own: main.c's on_int is handlers.c's. */
static void on_int(int sig) {
    (void)sig;
    signal(SIGUSR1, SIG_DFL);
}

void use_other(void) {
    on_int(0);
}
