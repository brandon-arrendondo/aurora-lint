/*
 * Rule: API05-C
 * Source: testcases
 * Status: PASS - Should NOT trigger API05-C violation
 */

/*
 * Reason: the void* param has no element type to count, and the size_t
 * param ("timeouts") is unrelated to it -- the old rule fired on ANY
 * pointer param whenever the signature had ANY size_t param anywhere,
 * without checking they were actually associated (task 190; real example:
 * curl's async_ares_rr_done(void *user_data, ..., size_t timeouts, ...)).
 */

#include <stddef.h>

void async_ares_rr_done(void *user_data, int x, size_t timeouts, int y)
{
    (void)user_data;
    (void)x;
    (void)timeouts;
    (void)y;
}
