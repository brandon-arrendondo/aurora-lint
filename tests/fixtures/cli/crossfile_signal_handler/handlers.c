#include <signal.h>
#include "handlers.h"

volatile sig_atomic_t interrupted;

void on_int(int sig) {
    (void)sig;
    interrupted = 1;
}
