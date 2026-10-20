/*
 * Rule: ENV32-C
 * Source: aurora-lint
 * Status: FAIL - the exit handler calls the library exit()
 *
 * A local named `exit` shadows the library function only inside its own
 * block; the call after that block is exit() itself.
 */
#include <stdlib.h>

typedef void (*hook_fn)(void);

extern hook_fn current_hook(void);

static void bye(void) {
    {
        hook_fn exit = current_hook();
        if (exit) {
            exit();
        }
    }
    exit(1);
}

int main(void) {
    atexit(bye);
    return 0;
}
