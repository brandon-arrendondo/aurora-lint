/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - POSIX is declared, so every preset reads the descriptor form
 * Settings: posix_version=2008
 * Expect: default=violation strict=violation pedantic=violation
 */
#include <unistd.h>

void f(int fd) {
    close(fd);
    close(fd);
}
