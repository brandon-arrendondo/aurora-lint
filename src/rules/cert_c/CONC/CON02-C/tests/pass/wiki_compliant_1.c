/*
 * Rule: CON02-C
 * Source: wiki
 * Status: PASS - Should NOT trigger CON02-C violation
 */

#include <threads.h>

int account_balance;
mtx_t flag;

/* Initialize flag */

int debit(unsigned int amount) {
  if (mtx_lock(&flag) == thrd_error) {
    return -1;  /* Indicate error */
  }
 
  account_balance -= amount; /* Inside critical section */

  if (mtx_unlock(&flag) == thrd_error) {
    return -1;  /* Indicate error */
  }

  return 0;
}