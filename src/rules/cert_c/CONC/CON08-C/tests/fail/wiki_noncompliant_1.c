/*
 * Rule: CON08-C
 * Source: wiki
 * Status: FAIL - Should trigger CON08-C violation
 */

#include <threads.h>
#include <stdio.h>
#include <stdbool.h>
 
static int a = 0;
static int b = 0;
mtx_t lock;
 
bool init_mutex(int type) {
  /* Validate type */
  if (thrd_success != mtx_init(&lock, type)) {
    return false;  /* Report error */
  }
  return true;
}

void set_values(int new_a, int new_b) {
  if (thrd_success != mtx_lock(&lock)) {
    /* Handle error */
  }
  a = new_a;
  b = new_b;
  if (thrd_success != mtx_unlock(&lock)) {
    /* Handle error */
  }
}

int get_sum(void) {
  if (thrd_success != mtx_lock(&lock)) {
    /* Handle error */
  }
  int sum = a + b;
  if (thrd_success != mtx_unlock(&lock)) {
    /* Handle error */
  }
  return sum;
}
  
int get_product(void) {
  if (thrd_success != mtx_lock(&lock)) {
    /* Handle error */
  }
  int product = a * b;
  if (thrd_success != mtx_unlock(&lock)) {
    /* Handle error */
  }
  return product;
}

/* Can be called by multiple threads */
void multiply_monomials(int x1, int x2) {
  printf("(x + %d)(x + %d)\n", x1, x2);
  set_values( x1, x2);
  printf("= x^2 + %dx + %d\n", get_sum(), get_product());
}