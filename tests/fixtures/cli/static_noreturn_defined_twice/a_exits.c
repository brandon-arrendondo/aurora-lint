/*
 * A static helper named die() that ends the process. It is this file's own:
 * b_returns.c defines its own static die(), which returns.
 */
#include <stdlib.h>

static void die(void) { exit(1); }

void a_entry(int e) {
    if (e)
        die();
}
