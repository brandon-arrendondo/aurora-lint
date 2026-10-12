/*
 * Rule: CON05-C
 * Source: testcases
 * Status: FAIL - Should trigger CON05-C violation
 *
 * A POSIX mutex is held across a blocking receive. CON05-C reads every
 * thread API's locks.
 */

#include <pthread.h>
#include <sys/socket.h>

pthread_mutex_t lock;
int last;

void update(int sock) {
    int value;
    pthread_mutex_lock(&lock);
    /* VIOLATION: recv() can block while the lock is held */
    recv(sock, &value, sizeof value, 0);
    last = value;
    pthread_mutex_unlock(&lock);
}
