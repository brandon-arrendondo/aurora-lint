/*
 * Rule: EXP42-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#include <string.h>
 
#pragma pack(push, 1)
struct s {
  char c;
  int i;
  char buffer[13];
};
#pragma pack(pop)
 
void compare(const struct s *left, const struct s *right) {  
  if ((left && right) &&
      (0 == memcmp(left, right, sizeof(struct s)))) {
    /* ... */
  }
}