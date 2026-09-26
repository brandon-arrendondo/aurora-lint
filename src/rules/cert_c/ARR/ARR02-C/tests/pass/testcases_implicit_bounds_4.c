/*
 * Rule: ARR02-C
 * Source: testcases
 * Status: PASS - ARR02-C-EX1: a character array initialized by a string
 * literal may omit its bound (STR11-C asks for exactly that)
 */

#include <stdio.h>

int main() {
    char text[] = "implicit sizing";

    printf("%s\n", text);
    return 0;
}
