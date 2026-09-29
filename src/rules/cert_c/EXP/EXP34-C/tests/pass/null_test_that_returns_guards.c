/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * The NULL branch logs and then returns, so the member access is reached
 * only with `p` non-null.
 */
#include <stddef.h>

struct s { int a; };
void log_msg(const char *m);

int read_a(struct s *p) {
    if (p == NULL) {
        log_msg("null");
        return -1;
    }
    return p->a;
}
