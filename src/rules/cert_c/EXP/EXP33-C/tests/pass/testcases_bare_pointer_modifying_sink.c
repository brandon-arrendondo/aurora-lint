/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation. `fds` is declared
 * with no initializer and passed BY VALUE (bare, not `&fds`) to set_fds(),
 * which writes through it purely via the POSIX FD_ZERO/FD_SET macros (task
 * 456; hostap's eloop_sock_table_set_fds pattern). Those are opaque system
 * macros aurora-lint's macro-expansion engine has no definition for, so the
 * only way to see the write is FunctionSummary's `modifies_params` (from
 * the intra-file prescan here, or a cross-file one via `-d`) recognizing
 * the FD_ZERO/FD_SET call -- and the read-check at the call-argument
 * position itself must consult that summary too, not just the post-call
 * state transfer, since `fds` is unsafe to read *before* the call updates
 * its state.
 */
#include <sys/select.h>

void set_fds(fd_set *fds) {
    FD_ZERO(fds);
    FD_SET(0, fds);
}

void f(void) {
    fd_set *fds;
    set_fds(fds);
    (void)select(1, fds, NULL, NULL, NULL);
}
