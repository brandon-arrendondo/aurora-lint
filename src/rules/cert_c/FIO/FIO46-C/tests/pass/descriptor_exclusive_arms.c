/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - the two closes are in arms of one #if chain, or in a noreturn path
 * Settings: posix_version=2008
 */
#include <unistd.h>

#include <stdlib.h>

#define HAVE_X 1

void arms(int fd) {
#ifdef HAVE_X
    close(fd);
#else
    close(fd);
#endif
}

void child(int fd) {
    if (fork() == 0) {
        close(fd);
        _exit(0);
    }
    close(fd);
}
