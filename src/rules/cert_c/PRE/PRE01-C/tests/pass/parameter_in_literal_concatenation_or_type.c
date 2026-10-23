/*
 * Rule: PRE01-C
 * Source: testcases
 * Status: PASS - Should NOT trigger PRE01-C violation
 *
 * Each parameter use below sits where parentheses would not compile, so it
 * cannot be parenthesized:
 * - next to a string literal, in a string concatenation: `(msg) "\n"` is
 *   not a valid expression;
 * - in a type position: the type of a declaration (`T count`) or the whole
 *   type name of a cast up to its pointer declarators (`(T *)0`).
 */

#include <stdio.h>
#include <stddef.h>

#define PUTLINE(msg) puts(msg "\n")
#define PREFIXED(msg) puts("log: " msg)
#define DECLARE_COUNT(T) T count = 0
#define NULL_OF(T) ((T *)0)
#define NULL_OF_PTR(T) ((T **)0)
#define SIZE_OF_PTR(T) sizeof(T *)

int main(void) {
    DECLARE_COUNT(int);
    PUTLINE("done");
    PREFIXED("ready");
    return count + (NULL_OF(char) == NULL) + (NULL_OF_PTR(int) == NULL) + (int)SIZE_OF_PTR(long);
}
