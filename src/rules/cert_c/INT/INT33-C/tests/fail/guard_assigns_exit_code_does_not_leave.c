/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The zero branch only assigns a variable named like exit()
 *
 * `exit_code = 1;` spells "exit" but calls nothing: control falls out of
 * the branch into the division. A guard's branch leaves only through a
 * return, break or continue, or a call to a function that never returns.
 */
#include <stdlib.h>

int divide(int a, int b)
{
    int exit_code = 0;
    if (b == 0) {
        exit_code = 1;
    }
    return a / b + exit_code;
}
