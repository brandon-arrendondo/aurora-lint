/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - a function of the project can open what a global, member or element holds
 * Settings: posix_version=2008
 */
#include <unistd.h>

int datafd = -1;
int fds[2];

struct conn {
    int fd;
};

void reconnect(void);

void global(void) {
    close(datafd);
    reconnect();
    close(datafd);
}

void member(struct conn *c) {
    close(c->fd);
    reconnect();
    close(c->fd);
}

void element(void) {
    close(fds[0]);
    reconnect();
    close(fds[0]);
}
