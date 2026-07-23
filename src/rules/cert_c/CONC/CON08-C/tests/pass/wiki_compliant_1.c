/*
 * Rule: CON08-C
 * Source: wiki
 * Status: PASS - Should NOT trigger CON08-C violation
 */

#include <threads.h>
#include <stdio.h>
#include <stdbool.h>

extern void set_values(int, int);
extern int get_sum(void);
extern int get_product(void);

mtx_t lock;
 
bool init_mutex(int type) {
  /* Validate type */
  if (thrd_success != mtx_init(&lock, type | mtx_recursive)) {
    return false;  /* Report error */
  }
  return true;
}

/* Can be called by multiple threads */
void multiply_monomials(int x1, int x2) {
  if (thrd_success != mtx_lock(&lock)) {
    /* Handle error */
  }
  set_values( x1, x2);
  int sum = get_sum();
  int product = get_product();
  if (thrd_success != mtx_unlock(&lock)) {
    /* Handle error */
  }

  printf("(x + %d)(x + %d)\n", x1, x2);
  printf("= x^2 + %dx + %d\n", sum, product);
}