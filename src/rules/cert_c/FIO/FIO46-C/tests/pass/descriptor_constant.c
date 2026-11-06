/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - a constant number can be open again: open returns the lowest free one
 * Settings: posix_version=2008
 */
#include <unistd.h>

#include <fcntl.h>

#define LOG_FD 3

enum { DATA_FD = 4 };

static const int FILE_FD = 5;

void f(void) {
    close(0);
    open("/dev/null", O_RDONLY);
    close(0);
    close(STDOUT_FILENO);
    close(STDOUT_FILENO);
    close(LOG_FD);
    close(LOG_FD);
    close(DATA_FD);
    close(DATA_FD);
    close(FILE_FD);
    close(FILE_FD);
    const int local_fd = 6;
    close(local_fd);
    close(local_fd);
}
