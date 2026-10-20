/*
 * Rule: FIO42-C
 *
 * Status: FAIL - Should trigger FIO42-C violation
 *
 * UNUSED() expands to a cast to void: it makes no call and stores nothing,
 * so it cannot close or keep the descriptor it is given.
 */
#include <fcntl.h>
#include <unistd.h>

#define UNUSED(V) ((void)V)

void touch(const char *path)
{
    int fd = open(path, O_RDONLY);
    UNUSED(fd);
    unlink(path);
}
