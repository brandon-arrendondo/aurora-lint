/*
 * Rule: CON07-C
 * Source: wiki
 * Status: FAIL - Should trigger CON07-C violation
 */

#include <stdbool.h>
 
static bool flag = false;
 
void toggle_flag(void) {
  flag = !flag;
}
 
bool get_flag(void) {
  return flag;
}