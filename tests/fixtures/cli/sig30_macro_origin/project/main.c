#include <setjmp.h>
#include <signal.h>
#include <unistd.h>
#include <sysalias.h>
#include "projalias.h"

struct ops {
    void (*log)(const char *);
};
#define CB(o) (o)->log("sig")

static struct ops *g;
static sigjmp_buf env;

static void on_alarm(int sig) {
    signal(sig, SIG_DFL);
    alarm(1);
    CB(g);
    siglongjmp(env, 1);
}

int main(void) {
    signal(SIGALRM, on_alarm);
    return 0;
}
