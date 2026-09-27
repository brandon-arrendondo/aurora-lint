/*
 * Rule: SIG30-C
 * Source: aurora-lint
 * Status: PASS - a logging macro whose body calls an alias of write()
 */

#include <signal.h>
#include <unistd.h>

#define xwrite write
#define LOG(msg) xwrite(2, (msg), sizeof(msg) - 1)

static void on_term(int sig) {
    (void)sig;
    LOG("term\n");
}

int main(void) {
    signal(SIGTERM, on_term);
    return 0;
}
