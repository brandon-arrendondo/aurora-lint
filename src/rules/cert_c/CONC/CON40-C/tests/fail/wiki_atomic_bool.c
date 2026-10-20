/*
 * Rule: CON40-C
 * Source: wiki
 * Status: FAIL - Should trigger CON40-C violation
 */

#include <stdatomic.h>
#include <stdbool.h>
  
static atomic_bool flag = ATOMIC_VAR_INIT(false);
  
void init_flag(void) {
  atomic_init(&flag, false);
}
  
void toggle_flag(void) {
  atomic_store(&flag, !atomic_load(&flag));
}
    
bool get_flag(void) {
  return atomic_load(&flag);
}