/*
 * Rule: FIO42-C
 *
 * Status: FAIL - Should trigger FIO42-C violation
 *
 * UNUSED() expands to a cast to void: it makes no call and stores nothing,
 * so it cannot close or keep the descriptor it is given. LOG_FD() only hands
 * it to printf(), which reads it.
 */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define UNUSED(V) ((void)V)
#define LOG_FD(fd) printf("opened %d\n", fd)

void touch(const char *path)
{
    int fd = open(path, O_RDONLY);
    UNUSED(fd);
    unlink(path);
}

void trace(const char *path)
{
    int fd = open(path, O_RDONLY);
    LOG_FD(fd);
}
