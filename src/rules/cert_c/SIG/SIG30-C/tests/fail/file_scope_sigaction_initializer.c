/*
 * Rule: SIG30-C
 * Source: aurora-lint
 * Status: FAIL - the handler is named in a file-scope struct sigaction initializer
 */

#include <signal.h>
#include <stdio.h>

static void on_term(int sig) {
    printf("terminating %d\n", sig);
}

static struct sigaction term_action = { .sa_handler = on_term };

int main(void) {
    sigaction(SIGTERM, &term_action, NULL);
    return 0;
}
