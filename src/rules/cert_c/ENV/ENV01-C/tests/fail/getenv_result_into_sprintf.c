/*
 * Rule: ENV01-C
 * Source: real-world shape
 * Status: FAIL - sprintf's %s argument is a getenv() result, no bound
 */

#include <stdio.h>
#include <stdlib.h>

void f(void) {
  char path[64];
  sprintf(path, "%s/.config", getenv("HOME"));
}
