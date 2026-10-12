/*
 * Rule: CON37-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON37-C violation
 *
 * The callback parameter is named thrd_create, but it is an object, not the
 * C11 function (resolved by declaration): nothing here starts a thread.
 */

#include <signal.h>

static void on_int(int sig) { (void)sig; }

int install(int (*thrd_create)(void)) {
    signal(SIGINT, on_int);
    return thrd_create();
}
