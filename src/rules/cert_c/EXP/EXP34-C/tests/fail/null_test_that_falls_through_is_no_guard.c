/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * The NULL branch logs and falls through, so `p` reaches the member access
 * NULL along it. Only a test whose NULL branch leaves guards what follows.
 */
#include <stddef.h>

struct s { int a; };
void log_msg(const char *m);

int read_a(struct s *p) {
    if (p == NULL) {
        log_msg("null");
    }
    return p->a;
}
