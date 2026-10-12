/*
 * Rule: CON32-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON32-C violation
 *
 * Both bit-field writes are made under a POSIX timed lock. Lock calls are
 * read by their thread-API contract, so every lock form counts.
 */

#include <pthread.h>
#include <time.h>

struct multi_threaded_flags {
  unsigned int flag1 : 2;
  unsigned int flag2 : 2;
};

struct multi_threaded_flags flags;
pthread_mutex_t flags_lock = PTHREAD_MUTEX_INITIALIZER;

void *thread1(void *arg) {
  const struct timespec *deadline = arg;
  if (pthread_mutex_timedlock(&flags_lock, deadline) == 0) {
    flags.flag1 = 1;
    pthread_mutex_unlock(&flags_lock);
  }
  return NULL;
}

void *thread2(void *arg) {
  const struct timespec *deadline = arg;
  if (pthread_mutex_timedlock(&flags_lock, deadline) == 0) {
    flags.flag2 = 2;
    pthread_mutex_unlock(&flags_lock);
  }
  return NULL;
}
