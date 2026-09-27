/*
 * An external die() that ends the process. b_returns.c defines its own
 * static die(), which returns, and its calls reach that one.
 */
#include <stdlib.h>

void die(void) { exit(1); }
