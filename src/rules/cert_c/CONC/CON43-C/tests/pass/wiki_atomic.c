/*
 * Rule: CON43-C
 * Source: wiki
 * Status: PASS - Should NOT trigger CON43-C violation
 */

#include <stdatomic.h>

atomic_int account_balance;

void debit(int amount) {
  account_balance -= amount;
}

void credit(int amount) {
  account_balance += amount;
}