/*
 * Rule: POS52-C
 * Source: testcases
 * Status: PASS - Should NOT trigger POS52-C violation
 *
 * A lock reached only through && is not taken on every path: the write
 * in the else branch, and the one after the bare short-circuit, may run
 * without the mutex.
 */

#include <pthread.h>
#include <unistd.h>

pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;

void conditional(int x, int fd, const char *b) {
  if (x && pthread_mutex_lock(&m) == 0) {
    pthread_mutex_unlock(&m);
  } else {
    write(fd, b, 1);
  }
}

void short_circuit(int x, int fd, const char *b) {
  x && pthread_mutex_lock(&m);
  write(fd, b, 1);
}
