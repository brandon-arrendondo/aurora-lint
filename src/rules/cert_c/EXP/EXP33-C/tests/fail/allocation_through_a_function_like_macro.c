/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * A function-like macro is classified as its expansion, through a second
 * macro and a cast: new_buf(8) is ((char *)malloc(8)).
 */

#include <stdlib.h>

#define my_malloc(n) malloc(n)
#define new_buf(n) ((char *)my_malloc(n))

char through_macros(void) {
    char *p = new_buf(8);
    char c = p[0]; /* VIOLATION */
    free(p);
    return c;
}
