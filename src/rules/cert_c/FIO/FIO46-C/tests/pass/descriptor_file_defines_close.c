/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - a file whose close is its own function is not closing a descriptor
 * Settings: posix_version=2008
 */
#include <unistd.h>

static void close_all(void);

int close(int fd) {
    (void)fd;
    close_all();
    return 0;
}

void f(int fd) {
    close(fd);
    close(fd);
}
