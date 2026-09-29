/*
 * Rule: EXP34-C
 * Source: wiki
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * CERT's compliant example leaves each NULL branch as the placeholder
 * `/* Handle error */`. Read literally that branch falls through to the
 * dereference, so it guards nothing; the placeholder stands for code that
 * leaves, and this copy spells that out as an explicit return.
 */

#include <string.h>
#include <stdlib.h>
 
void f(const char *input_str) {
  size_t size;
  char *c_str;
 
  if (NULL == input_str) {
    /* Handle error */
    return;
  }
  
  size = strlen(input_str) + 1;
  c_str = (char *)malloc(size);
  if (NULL == c_str) {
    /* Handle error */
    return;
  }
  memcpy(c_str, input_str, size);
  /* ... */
  free(c_str);
  c_str = NULL;
  /* ... */
}