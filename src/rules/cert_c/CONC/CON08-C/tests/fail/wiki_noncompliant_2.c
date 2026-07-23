/*
 * Rule: CON08-C
 * Source: wiki (Noncompliant Code Example 2 - function chaining variant)
 * Status: FAIL - Should trigger CON08-C violation
 *
 * Each set_* function is individually atomic (uses global mutex),
 * but init_45_cents/init_60_cents call multiple atomic functions
 * without wrapping the group in a mutex — race condition.
 */

#include <threads.h>
#include <stdio.h>

typedef struct currency_s {
  int quarters;
  int dimes;
  int nickels;
  int pennies;
} currency_t;

mtx_t currency_lock;

currency_t *set_quarters(int quantity, currency_t *currency) {
  if (thrd_success != mtx_lock(&currency_lock)) {
    /* Handle error */
  }
  currency->quarters += quantity;
  if (thrd_success != mtx_unlock(&currency_lock)) {
    /* Handle error */
  }
  return currency;
}
currency_t *set_dimes(int quantity, currency_t *currency) {
  if (thrd_success != mtx_lock(&currency_lock)) {
    /* Handle error */
  }
  currency->dimes += quantity;
  if (thrd_success != mtx_unlock(&currency_lock)) {
    /* Handle error */
  }
  return currency;
}
currency_t *set_nickels(int quantity, currency_t *currency) {
  if (thrd_success != mtx_lock(&currency_lock)) {
    /* Handle error */
  }
  currency->nickels += quantity;
  if (thrd_success != mtx_unlock(&currency_lock)) {
    /* Handle error */
  }
  return currency;
}
currency_t *set_pennies(int quantity, currency_t *currency) {
  if (thrd_success != mtx_lock(&currency_lock)) {
    /* Handle error */
  }
  currency->pennies += quantity;
  if (thrd_success != mtx_unlock(&currency_lock)) {
    /* Handle error */
  }
  return currency;
}

/* Noncompliant: calls multiple atomic functions without wrapping in mutex */
int init_45_cents(void *currency) {
  currency_t *c = set_quarters(1, set_dimes(2, currency));
  /* Validate values are correct */
  return 0;
}
int init_60_cents(void* currency) {
  currency_t *c = set_quarters(2, set_dimes(1, currency));
  /* Validate values are correct */
  return 0;
}

int main(void) {
  thrd_t thrd1;
  thrd_t thrd2;
  currency_t currency = {0, 0, 0, 0};

  if (thrd_success != mtx_init(&currency_lock, mtx_plain)) {
    /* Handle error */
  }
  if (thrd_success != thrd_create(&thrd1, init_45_cents, &currency)) {
    /* Handle error */
  }
  if (thrd_success != thrd_create(&thrd2, init_60_cents, &currency)) {
    /* Handle error */
  }
  if (thrd_success != thrd_join(thrd1, NULL)) {
    /* Handle error */
  }
  if (thrd_success != thrd_join(thrd2, NULL)) {
    /* Handle error */
  }

  printf("%d quarters, %d dimes, %d nickels, %d pennies\n",
         currency.quarters, currency.dimes, currency.nickels, currency.pennies);

  mtx_destroy(&currency_lock);
  return 0;
}
