/*
 * Rule: SIG31-C
 * Source: aurora-lint
 * Status: FAIL - an unknown calling-convention macro sends the parse of this
 * function-pointer typedef into recovery, which leaves it reading as
 * `typedef volatile sig_atomic_t seen, DWORD`. `DWORD` is the next
 * parameter's type, not a name for `volatile sig_atomic_t`, so the handler's
 * write to `hits` is still to an object of the wrong type.
 */

#include <signal.h>

typedef LONG (WINAPI * PFN_Note)(HKEY hKey, volatile sig_atomic_t seen, DWORD count);

static DWORD hits;

static void on_int(int sig) {
    (void)sig;
    hits = 1;
}

int main(void) {
    signal(SIGINT, on_int);
    return 0;
}
