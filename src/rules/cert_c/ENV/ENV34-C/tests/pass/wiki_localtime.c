/*
 * Rule: ENV34-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#include <stdio.h>
#include <threads.h>
#include <time.h>

char now[1024];

int how_soon_is_now(void *) {
  time_t n1;
  if ((time_t) -1 == time(&n1)) {
    // Handle Error
  }
  if (strftime(now, sizeof now, "%Y-%m-%d %H:%M:%S %Z",
               localtime(&n1)) <=  0) {
    // Handle Error
  }
  return 0;
}

int main(void) {
  thrd_t thr;
  if (thrd_success != thrd_create(&thr, how_soon_is_now, 0)) {
    // Handle Error
  }

  int retval;
  if (thrd_success != thrd_join(thr, &retval)) {
    // Handle Error
  }

  puts("The time is: ");
  puts(now);
  return 0;
}