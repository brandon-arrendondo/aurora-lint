/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - the bound allows a second pass, which closes it again
 * Settings: posix_version=2008
 */
#include <unistd.h>

void f(int fd) {
    int k;
    for (k = 0; k < 2; k++) {
        close(fd);
    }
}
