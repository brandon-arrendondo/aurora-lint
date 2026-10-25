#include <signal.h>

/* Shares its name with the handler main.c registers, but is this file's
 * own: main.c's on_term is handlers.c's. */
static int count;

static void on_term(int sig) {
    (void)sig;
    count++;
}

void use_other(void) {
    on_term(0);
}
