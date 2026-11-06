/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - the target is declared not POSIX, under every preset
 * Settings: posix_version=none
 * Expect: default=clean strict=clean pedantic=clean
 */
#include <unistd.h>

void f(int fd) {
    close(fd);
    close(fd);
}
