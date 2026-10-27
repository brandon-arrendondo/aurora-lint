/*
 * Rule: DCL20-C
 * Source: synthetic
 * Status: FAIL - Should trigger DCL20-C violation
 * Expect: count=6
 *
 * An empty parameter list declares a function without a prototype whatever
 * the declarator around it: a pointer return, a pointer to pointer, a pointer
 * to a function returning a pointer, or an array of function pointers.
 */

struct node;

char *pf(); /* Expect: here */
struct node *mk(); /* Expect: here */
const char **names(); /* Expect: here */
int **ipp(); /* Expect: here */
char *(*fp)(); /* Expect: here */
int (*table[4])(); /* Expect: here */
