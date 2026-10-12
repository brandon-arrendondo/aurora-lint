/*
 * Rule: POS52-C
 * Source: testcases
 * Status: PASS - Should NOT trigger POS52-C violation
 *
 * The lock is a C11 mutex: CON05-C reports the receive. POS52-C reads POSIX
 * locks.
 */

#include <sys/socket.h>
#include <threads.h>

mtx_t lock;

void update(int sock, char *buf) {
    mtx_lock(&lock);
    recv(sock, buf, 1, 0);
    mtx_unlock(&lock);
}
