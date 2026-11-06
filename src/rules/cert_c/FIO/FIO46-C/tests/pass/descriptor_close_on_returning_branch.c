/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - a close on a branch that returns reaches nothing after it
 * Settings: posix_version=2008
 */
#include <unistd.h>

int f(int fd, int c) {
    if (c) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}
