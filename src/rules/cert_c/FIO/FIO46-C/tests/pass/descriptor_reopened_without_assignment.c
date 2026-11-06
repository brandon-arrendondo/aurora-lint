/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - dup2, pipe, socketpair and a pointer each give the name a new descriptor
 * Settings: posix_version=2008
 */
#include <unistd.h>

#include <sys/socket.h>

void reopen(int *out);

void by_dup2(int fd, int other) {
    close(fd);
    dup2(other, fd);
    close(fd);
}

void by_pipe(void) {
    int p[2];
    pipe(p);
    close(p[0]);
    pipe(p);
    close(p[0]);
}

void by_socketpair(void) {
    int p[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, p);
    close(p[0]);
    socketpair(AF_UNIX, SOCK_STREAM, 0, p);
    close(p[0]);
}

void by_pointer(void) {
    int fd = -1;
    reopen(&fd);
    close(fd);
    reopen(&fd);
    close(fd);
}
