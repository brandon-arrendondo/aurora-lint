/*
 * Rule: DCL37-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

/* Not including stdlib.h */
void free(void *);
 
void func(void *ptr) {
  free(ptr);
}