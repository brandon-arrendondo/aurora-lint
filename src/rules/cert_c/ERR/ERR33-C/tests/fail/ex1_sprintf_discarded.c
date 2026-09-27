/*
 * Rule: ERR33-C
 * Status: FAIL - sprintf() is not in ERR33-C-EX1: a discarded result is
 * reported whatever the destination.
 */

#include <stdio.h>

void f(char *buf, int i) {
    sprintf(buf, "%d", i);
}
