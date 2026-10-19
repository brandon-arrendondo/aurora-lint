/*
 * Rule: MSC13-C
 * Status: FAIL - Dead store: value overwritten before being read. An
 * assignment, unlike a default value on the declaration (MSC13-EX1), is
 * never exempt.
 */

#include <stdio.h>

void f(void) {
    int data;
    data = 'C';   /* VIOLATION: dead store — overwritten on next line */
    data = 'Z';
    printf("%c\n", data);
}
