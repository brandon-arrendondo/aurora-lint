/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: FAIL - Should trigger PRE31-C violation
 *
 * In a release build DEBUG_COUNT discards its argument, and the increment
 * with it, so `(*hits)++` runs in one configuration and not in the other.
 * Evaluating an argument zero times is as unsafe as evaluating it twice.
 */

#ifdef NDEBUG
#define DEBUG_COUNT(x) ((void)0)
#else
#define DEBUG_COUNT(x) record_count(x)
#endif

void record_count(int n);

void on_hit(int *hits)
{
    DEBUG_COUNT((*hits)++);  /* VIOLATION: the increment vanishes under NDEBUG */
}
