/*
 * Rule: POS52-C
 * Source: testcases
 * Status: PASS - Should NOT trigger POS52-C violation
 *
 * A function-like macro the project defines under a library function's name
 * replaces every later call of that name. Here "pthread_mutex_lock" takes
 * the project's own lock, which this rule does not read as a POSIX mutex.
 * "write" becomes the project's non-blocking write, which does not block
 * under the real mutex.
 */

#include <pthread.h>
#include <unistd.h>

int my_lock(void *m);
int my_unlock(void *m);
long nb_write(int fd, const void *b, unsigned long n);

pthread_mutex_t real = PTHREAD_MUTEX_INITIALIZER;

void through_a_project_write(int fd, const char *b) {
  pthread_mutex_lock(&real);
#define write(fd, b, n) nb_write(fd, b, n)
  write(fd, b, 1);
#undef write
  pthread_mutex_unlock(&real);
}

#define pthread_mutex_lock(m) my_lock(m)
#define pthread_mutex_unlock(m) my_unlock(m)

void under_a_project_lock(int fd, const char *b, void *own) {
  pthread_mutex_lock(own);
  write(fd, b, 1);
  pthread_mutex_unlock(own);
}
