/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - the one call closes it again on the next pass
 * Settings: posix_version=2008
 */
#include <unistd.h>

void f(int fd, int n) {
    for (int i = 0; i < n; i++) {
        close(fd);
    }
}
