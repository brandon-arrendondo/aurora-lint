/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - the do loop's condition may hold, so a second pass closes it again
 * Settings: posix_version=2008
 */
#include <unistd.h>

void f(int fd, int again) {
    do {
        close(fd);
    } while (again);
}
