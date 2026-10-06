/*
 * Rule: DCL31-C
 * Source: real-world (curl lib/cw-out.c, scope check)
 * Status: FAIL - a parameter declares its name only inside its own function.
 *
 * `cb` is a parameter of `uses_param`, so calling it there is fine; in
 * `no_such_param` nothing declares `cb`, and that call must still be
 * reported.
 */

#include "unseen_api.h" /* would declare: typedef int (*cb_t)(int); */

int uses_param(cb_t cb)
{
    return cb(1);
}

int no_such_param(void)
{
    return cb(2);
}
