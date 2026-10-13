/*
 * Rule: POS52-C
 * Source: testcases
 * Status: PASS - Should NOT trigger POS52-C violation
 *
 * MSG_DONTWAIT as a term of a bitwise OR is always set, whatever the
 * other terms are, so neither receive blocks.
 */

#include <pthread.h>
#include <sys/socket.h>

pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;

void peek(int sock, char *b, int extra) {
  pthread_mutex_lock(&m);
  recv(sock, b, 1, MSG_PEEK | (MSG_DONTWAIT | MSG_TRUNC));
  recv(sock, b, 1, extra | MSG_DONTWAIT);
  pthread_mutex_unlock(&m);
}
