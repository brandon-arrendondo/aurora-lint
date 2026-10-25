#include <signal.h>
#include "handlers.h"

sig_atomic_t flag;
volatile sig_atomic_t done;

void on_term(int sig) {
    (void)sig;
    flag = 1;
    done = 1;
}
