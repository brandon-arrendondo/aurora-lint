/*
 * Rule: CON05-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON05-C violation
 *
 * The project defines its own write(), a ring-buffer append that cannot
 * block, so the call under the lock is not the POSIX function.
 */

#include <threads.h>

mtx_t lock;
static char ring[256];
static unsigned head;

static int write(int fd, const void *p, unsigned n) {
    (void)fd;
    for (unsigned i = 0; i < n; i++) {
        ring[(head + i) % sizeof ring] = ((const char *)p)[i];
    }
    head += n;
    return (int)n;
}

void log_byte(char c) {
    mtx_lock(&lock);
    write(0, &c, 1);
    mtx_unlock(&lock);
}
