/*
 * Rule: DCL01-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

extern int name;
void f(char *name);  /* Declaration: no problem here */
/* ... */
void f(char *arg) {  /* Definition: no problem; arg doesn't hide name */
  /* Use arg */
}