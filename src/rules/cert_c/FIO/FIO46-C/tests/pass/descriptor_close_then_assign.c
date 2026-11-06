/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - the assignment ends the closed descriptor
 * Settings: posix_version=2008
 */
#include <unistd.h>

void f(int fd) {
    close(fd);
    fd = -1;
    close(fd);
}
