#include <signal.h>
#include <unistd.h>
#include "remap.h"

static void on_alarm(int sig) {
    (void)sig;
    alarm(1);
}

int main(void) {
    signal(SIGALRM, on_alarm);
    return 0;
}
