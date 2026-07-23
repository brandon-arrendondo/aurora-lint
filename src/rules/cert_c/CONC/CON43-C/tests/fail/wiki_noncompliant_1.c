/*
 * Rule: CON43-C
 * Source: wiki
 * Status: FAIL - Should trigger CON43-C violation
 */

static volatile int account_balance;

void debit(int amount) {
  account_balance -= amount;
}

void credit(int amount) {
  account_balance += amount;
}