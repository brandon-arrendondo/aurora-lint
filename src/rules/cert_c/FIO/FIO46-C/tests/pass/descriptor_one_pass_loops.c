/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - a loop that runs its body once, or never, has no earlier pass
 * Settings: posix_version=2008
 */
#include <unistd.h>

#define CLOSE_FD(fd) do { close(fd); } while (0)

void macro_statement(int fd) {
    CLOSE_FD(fd);
}

void do_while_zero(int fd) {
    do {
        close(fd);
    } while (0);
}

void counted_once(int fd) {
    int k;
    for (k = 0; k < 1; k++) {
        close(fd);
    }
}

void counted_once_declared(int fd) {
    for (int j = 0; j < 1; j++) {
        close(fd);
    }
}

void dead_while(int fd) {
    while (0) {
        close(fd);
    }
    close(fd);
}
