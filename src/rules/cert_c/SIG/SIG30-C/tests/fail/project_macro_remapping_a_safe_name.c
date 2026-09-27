/*
 * Rule: SIG30-C
 * Source: aurora-lint
 * Status: FAIL - the project maps write() onto a logging function, so the handler calls that
 */

#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static void log_and_write(int fd, const void *buf, unsigned len) {
    fprintf(stderr, "writing %u bytes\n", len);
    (void)fd;
    (void)buf;
}

#define write log_and_write

static void on_term(int sig) {
    (void)sig;
    write(2, "term\n", 5);
}

int main(void) {
    signal(SIGTERM, on_term);
    return 0;
}
