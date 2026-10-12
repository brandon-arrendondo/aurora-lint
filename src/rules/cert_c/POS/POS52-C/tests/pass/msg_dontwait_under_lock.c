/*
 * Rule: POS52-C
 * Source: testcases
 * Status: PASS - Should NOT trigger POS52-C violation
 *
 * CERT's non-blocking compliant solution, with the receive made under the
 * lock: MSG_DONTWAIT makes recv() return at once.
 */

#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>

pthread_mutex_t mutex;

void thread_foo(int sock) {
  uint32_t num;
  int result;

  if ((result = pthread_mutex_lock(&mutex)) != 0) {
    /* Handle Error */
  }

  if ((result = recv(sock, (void *)&num, sizeof(uint32_t), MSG_DONTWAIT)) < 0) {
    /* Handle Error */
  }

  if ((result = pthread_mutex_unlock(&mutex)) != 0) {
    /* Handle Error */
  }
}
