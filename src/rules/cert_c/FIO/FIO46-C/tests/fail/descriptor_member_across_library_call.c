/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - a library call cannot write the member
 * Settings: posix_version=2008
 */
#include <unistd.h>

#include <stdio.h>

struct conn {
    int fd;
};

void f(struct conn *c) {
    close(c->fd);
    puts("closed");
    close(c->fd);
}
