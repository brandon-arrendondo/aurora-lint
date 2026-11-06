/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - each pass closes another element or another list node
 * Settings: posix_version=2008
 */
#include <unistd.h>

struct conn {
    int fd;
    struct conn *next;
};

void elements(int *fds, int n) {
    for (int i = 0; i < n; i++) {
        close(fds[i]);
    }
}

void nodes(struct conn *c) {
    for (; c; c = c->next) {
        close(c->fd);
    }
}

void opened_in_loop(int n) {
    for (int i = 0; i < n; i++) {
        int fd = dup(0);
        close(fd);
    }
}
