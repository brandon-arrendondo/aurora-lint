/*
 * Rule: MSC05-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC05-C violation
 */

int do_work(int seconds_to_work) {
  time_t start = time(NULL);

  if (start == (time_t)(-1)) {
    /* Handle error */
  }
  while (time(NULL) < start + seconds_to_work) {
    /* ... */
  }
  return 0;
}