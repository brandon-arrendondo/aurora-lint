/*
 * Rule: CON05-C
 * Source: testcases
 * Status: FAIL - Should trigger CON05-C violation
 *
 * The branch taken when pthread_mutex_lock() succeeds holds the mutex, and
 * so does the code after a failure branch that returns.
 */

#include <pthread.h>
#include <unistd.h>

pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;

void on_success(int fd, const char *b) {
  if (pthread_mutex_lock(&m) == 0) {
    write(fd, b, 1);
    pthread_mutex_unlock(&m);
  }
}

int after_failure(int fd, const char *b) {
  if (pthread_mutex_lock(&m)) {
    return -1;
  }
  write(fd, b, 1);
  pthread_mutex_unlock(&m);
  return 0;
}
