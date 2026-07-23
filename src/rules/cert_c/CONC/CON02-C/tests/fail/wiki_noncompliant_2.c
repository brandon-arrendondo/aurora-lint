/*
 * Rule: CON02-C
 * Source: wiki
 * Status: FAIL - Should trigger CON02-C violation
 */

volatile bool flag = false;

void test() {
  while (!flag){
    sleep(1000);
  }
}

void wakeup(){
  flag = true;
}

void debit(unsigned int amount) {
  test();
  account_balance -= amount;
}