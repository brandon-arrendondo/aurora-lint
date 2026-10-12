/*
 * Rule: POS52-C
 * Source: testcases
 * Status: FAIL - Should trigger POS52-C violation
 *
 * The first call in the statement does not block; the second one does.
 */

#include <pthread.h>
#include <sys/socket.h>

pthread_mutex_t lock;
int ready(int sock);

void pump(int sock, char *buf) {
    pthread_mutex_lock(&lock);
    /* VIOLATION: recv() can block while the lock is held */
    if (ready(sock) && recv(sock, buf, 1, 0) > 0) {
        buf[1] = 0;
    }
    pthread_mutex_unlock(&lock);
}
