/*
 * Rule: ENV32-C
 * Source: aurora-lint
 * Status: FAIL - an exit handler registered by address calls exit()
 */

#include <stdlib.h>

static void bye(void) {
    exit(1);
}

int main(void) {
    atexit(&bye);
    return 0;
}
