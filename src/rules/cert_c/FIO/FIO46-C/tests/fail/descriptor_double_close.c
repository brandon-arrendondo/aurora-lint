/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - the second close(fd) on one path
 * Expect: default=violation strict=clean pedantic=clean
 */
#include <unistd.h>

void f(int fd) {
    close(fd);
    close(fd);
}
