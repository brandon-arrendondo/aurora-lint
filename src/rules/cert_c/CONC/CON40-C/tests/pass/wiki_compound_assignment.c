/*
 * Rule: CON40-C
 * Source: wiki
 * Status: PASS - Should NOT trigger CON40-C violation
 */

#include <stdatomic.h>
#include <stdbool.h>
  
static atomic_bool flag = ATOMIC_VAR_INIT(false);
  
void toggle_flag(void) {
  flag ^= 1;
}
    
bool get_flag(void) {
  return flag;
}