/*
 * Rule: DCL20-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger DCL20-C violation
 *
 * The same declarators with a prototype: (void) or named parameter types.
 */

struct node;

char *pf(void);
struct node *mk(int key);
const char **names(void);
char *(*fp)(int);
int (*table[4])(void);
char *buf = 0, *(*getter)(const char *name);
