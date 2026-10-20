/*
 * Rule: ENV32-C
 * Source: aurora-lint (misfire: a local named `exit` read as exit())
 * Status: PASS - Should NOT trigger ENV32-C violation
 *
 * The exit handler calls through a local function pointer that happens to
 * be named `exit`. That is a call of whatever the hook points at, not of
 * the library exit(), and the handler returns normally.
 */
#include <stdlib.h>

typedef void (*hook_fn)(void);

extern hook_fn current_hook(void);

static void bye(void) {
    hook_fn exit = current_hook();
    if (exit) {
        exit();
    }
}

int main(void) {
    atexit(bye);
    return 0;
}
