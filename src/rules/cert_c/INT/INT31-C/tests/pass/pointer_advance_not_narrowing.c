/*
 * Rule: INT31-C
 * Source: task 914 (pure-ftpd safe_rw.c:56, puredb_read.c:39, quotas.c:74)
 * Status: PASS - Should NOT trigger INT31-C violation
 * Reason: `buf += readnb` advances a POINTER by an ssize_t. The type
 *         specifier alone made `unsigned char *buf` look like an 8-bit
 *         `unsigned char`, so a 64-bit RHS read as a narrowing assignment.
 *         A pointer has no integer width to narrow into.
 */

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

size_t safe_read(int fd, void *buf_, size_t count) {
    unsigned char *buf = (unsigned char *)buf_;
    size_t remaining = count;
    ssize_t readnb;

    while (remaining > (size_t)0) {
        readnb = read(fd, buf, remaining);
        if (readnb <= 0) {
            break;
        }
        remaining -= (size_t)readnb;
        buf += readnb;
    }
    return count - remaining;
}

/* Same shape on a pointer declared without an initializer, advanced by a
   value parsed from untrusted input. */
void walk_uninitialized(char *base) {
    char *bufpnt;
    long step = atol(getenv("STEP"));
    bufpnt = base;
    bufpnt += step;
    (void)bufpnt;
}
