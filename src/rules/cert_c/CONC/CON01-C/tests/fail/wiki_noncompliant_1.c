/*
 * Rule: CON01-C
 * Source: wiki
 * Status: FAIL - Should trigger CON01-C violation
 */

#include <threads.h>

enum { MIN_BALANCE = 50 };

int account_balance;
mtx_t mp;

/* Initialize mp */

int verify_balance(int amount) {
  if (account_balance - amount < MIN_BALANCE) {
    /* Handle error condition */
    if (mtx_unlock(&mp) ==  thrd_error) {
      /* Handle error */
    }
    return -1;
  }
  return 0;
}

void debit(int amount) {
  if (mtx_lock(&mp) == thrd_error) {
    /* Handle error */
  }
  if (verify_balance(amount) == -1) {
    if (mtx_unlock(&mp) == thrd_error) {
      /* Handle error */
    }
    return;
  }
  account_balance -= amount;
  if (mtx_unlock(&mp) == thrd_error) {
    /* Handle error */
  }
}