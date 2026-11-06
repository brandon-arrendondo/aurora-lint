/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - a variable holding 0 is still a variable, and is not a constant descriptor
 * Settings: posix_version=2008
 */
#include <unistd.h>

void f(void) {
    int fd = 0;
    close(fd);
    close(fd);
}

void opened(const char *path) {
    const int fd = dup(0);
    close(fd);
    close(fd);
}

void param(const int fd) {
    close(fd);
    close(fd);
}
