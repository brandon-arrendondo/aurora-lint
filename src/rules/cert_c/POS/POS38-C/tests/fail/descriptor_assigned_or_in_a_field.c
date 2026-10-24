/*
 * Rule: POS38-C
 * Source: synthetic
 * Status: FAIL - Should trigger POS38-C violation
 *
 * Both fork() arms read a descriptor the function opened before forking:
 * one assigned inside a test, `if ((fd = open(...)) < 0)`, and one stored
 * in a structure field, which has no declarator of its own and is matched
 * by its whole field path.
 */
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

struct session {
    int fd;
};

void assigned_in_test(void)
{
    char c;
    int fd;
    if ((fd = open("data", O_RDWR)) < 0)
        return;
    pid_t pid = fork();
    if (pid == 0) {
        read(fd, &c, 1);
    } else {
        read(fd, &c, 1);
    }
}

void field_descriptor(struct session *s)
{
    char c;
    s->fd = open("data", O_RDWR);
    pid_t pid = fork();
    if (pid == 0) {
        read(s->fd, &c, 1);
    } else {
        read(s->fd, &c, 1);
    }
}
