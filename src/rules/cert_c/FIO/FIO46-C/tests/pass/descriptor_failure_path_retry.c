/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - POSIX leaves a descriptor open or unspecified after a failed close
 * Settings: posix_version=2008
 */
#include <unistd.h>

#include <errno.h>

void tested(int fd) {
    if (close(fd) == -1) {
        close(fd);
    }
}

void negated(int fd) {
    if (!close(fd)) {
        return;
    }
    close(fd);
}

void eintr_loop(int fd) {
    while (close(fd) == -1 && errno == EINTR) {
    }
}

void eintr_stored(int fd) {
    int r;
    do {
        r = close(fd);
    } while (r == -1 && errno == EINTR);
}

void failing_loop(int fd) {
    while (close(fd) != 0) {
    }
}
