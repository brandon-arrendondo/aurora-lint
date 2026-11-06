/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - only a second close is the form: reading the int is not
 * Settings: posix_version=2008
 */
#include <unistd.h>

void f(int fd, char *buf) {
    close(fd);
    read(fd, buf, 1);
    (void)fd;
}
