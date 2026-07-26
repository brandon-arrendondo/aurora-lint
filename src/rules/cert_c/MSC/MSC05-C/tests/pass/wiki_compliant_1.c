/*
 * Rule: MSC05-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

int do_work(int seconds_to_work) {
  time_t start = time(NULL);
  time_t current = start;

  if (start == (time_t)(-1)) {
    /* Handle error */
  }
  while (difftime(current, start) < seconds_to_work) {
    current = time(NULL);
    if (current == (time_t)(-1)) {
       /* Handle error */
    }
    /* ... */
  }
  return 0;
}