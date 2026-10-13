/*
 * Rule: POS52-C
 * Source: testcases
 * Status: FAIL - Should trigger POS52-C violation
 *
 * Each receive may block: masking MSG_DONTWAIT out, choosing it only on
 * one arm, or passing it through a variable the analysis does not follow
 * leaves the flag possibly clear.
 */

#include <pthread.h>
#include <sys/socket.h>

pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;

void masked(int sock, char *b, int flags) {
  pthread_mutex_lock(&m);
  recv(sock, b, 1, flags & ~MSG_DONTWAIT);
  pthread_mutex_unlock(&m);
}

void chosen(int sock, char *b, int c) {
  pthread_mutex_lock(&m);
  recv(sock, b, 1, c ? MSG_DONTWAIT : 0);
  pthread_mutex_unlock(&m);
}

void through_a_variable(int sock, char *b) {
  int flags = MSG_DONTWAIT;
  pthread_mutex_lock(&m);
  recv(sock, b, 1, flags);
  pthread_mutex_unlock(&m);
}
