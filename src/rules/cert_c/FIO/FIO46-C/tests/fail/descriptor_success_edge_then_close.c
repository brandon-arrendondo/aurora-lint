/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - past a tested close that succeeded, a second close is a double close
 * Settings: posix_version=2008
 */
#include <unistd.h>

void f(int fd) {
    if (close(fd) < 0) {
        return;
    }
    close(fd);
}
