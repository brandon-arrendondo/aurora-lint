/*
 * Rule: CON32-C
 * Source: wiki
 * Status: PASS - Should NOT trigger CON32-C violation
 */

struct multi_threaded_flags {
  unsigned char flag1;
  unsigned char flag2;
};
 
struct multi_threaded_flags flags;
 
int thread1(void *arg) {
  flags.flag1 = 1;
  return 0;
}

int thread2(void *arg) {
  flags.flag2 = 2;
  return 0;
}