/*
 * Rule: POS52-C
 * Source: testcases
 * Status: FAIL - Should trigger POS52-C violation
 *
 * A macro that names the library function in its own replacement list still
 * calls that function: the preprocessor does not expand a macro inside its
 * own replacement. The counting write blocks while the mutex is held.
 */

#include <pthread.h>
#include <unistd.h>

extern unsigned long bytes_out;

#define write(fd, b, n) (bytes_out += (n), write(fd, b, n))

pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;

void counted(int fd, const char *b) {
  pthread_mutex_lock(&m);
  write(fd, b, 1);
  pthread_mutex_unlock(&m);
}
