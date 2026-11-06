/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - a close on a branch that falls through reaches the second
 * Settings: posix_version=2008
 */
#include <unistd.h>

void f(int fd, int c) {
    if (c) {
        close(fd);
    }
    close(fd);
}
