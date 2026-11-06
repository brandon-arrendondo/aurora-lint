/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - the file-scope descriptor is assigned after each close, and a goto retries the open
 * Settings: posix_version=2008
 */
#include <fcntl.h>
#include <unistd.h>

static int lock_fd = -1;

int open_lock(const char *path, int bad) {
anew:
    lock_fd = open(path, O_RDWR);
    if (lock_fd == -1) {
        return -1;
    }
    if (bad) {
        unlink(path);
        (void) close(lock_fd);
        lock_fd = -1;
        goto anew;
    }
    (void) close(lock_fd);
    lock_fd = -1;
    return 0;
}
