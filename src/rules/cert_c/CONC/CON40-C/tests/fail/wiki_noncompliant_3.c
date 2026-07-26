/*
 * Rule: CON40-C
 * Source: wiki
 * Status: FAIL - Should trigger CON40-C violation
 */

#include <stdatomic.h>
#include <stdbool.h>
  
static atomic_bool flag = false;
  
void init_flag(void) {
  atomic_init(&flag, false);
}
  
void toggle_flag(void) {
  bool temp_flag = atomic_load(&flag);
  temp_flag = !temp_flag;
  atomic_store(&flag, temp_flag);
}
    
bool get_flag(void) {
  return atomic_load(&flag);
}