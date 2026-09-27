/*
 * Rule: SIG30-C
 * Source: aurora-lint
 * Status: FAIL - an alias of write() in one #if arm and of a logging function in the other
 */

#include <signal.h>
#include <unistd.h>

void my_log(int fd, const char *msg, unsigned len);

#ifndef LOG_TO_FILE
#define xwrite write
#else
#define xwrite my_log
#endif

static void on_term(int sig) {
    (void)sig;
    xwrite(2, "term\n", 5);
}

int main(void) {
    signal(SIGTERM, on_term);
    return 0;
}
