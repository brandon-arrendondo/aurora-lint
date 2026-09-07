/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP33-C violation. `sscanf`'s argument 0 is
 * the string it PARSES, not one it writes, so an unwritten buffer handed to it
 * is a real uninitialized read. Crediting the scanf family by falling through
 * to the unknown-function `&var` fallback would have credited this buffer too;
 * modelling the variadic shape keeps argument 0 an input (task 1029).
 */
#include <stdio.h>

void use_int(int v);

void parse_from_unwritten_buffer(void) {
    char buf[64];
    int x;

    sscanf(buf, "%d", &x);
    use_int(x);
}
