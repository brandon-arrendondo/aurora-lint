/*
 * Rule: FIO42-C
 *
 * Status: FAIL - Should trigger FIO42-C violation
 *
 * The handle is returned only on the branch where the open failed, so
 * nothing is handed to the caller: on success the function returns another
 * value and the descriptor is never closed.
 */
#include <fcntl.h>
#include <unistd.h>

int read_header(const char *path, char *buf, unsigned n)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return fd;
    if (read(fd, buf, n) < 0)
        return -1;
    return 0;
}
