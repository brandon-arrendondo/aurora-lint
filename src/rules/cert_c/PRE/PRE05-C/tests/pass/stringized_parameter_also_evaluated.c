/*
 * Rule: PRE05-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger PRE05-C violation
 *
 * CHECK evaluates e as well as stringizing it, like assert: the evaluated
 * use is fully expanded, and #e only prints the condition as written.
 * NAME_OF does the same with a case label.
 */

#define CHECK(e) ((e) ? (void)0 : report_failure(#e))
#define NAME_OF(v) case v: return #v
#define LIMIT 16
#define in_range(x) ((x) < LIMIT)

void report_failure(const char *what);

void check(int n) { CHECK(in_range(n)); CHECK(LIMIT > 0); }

const char *state_name(int s)
{
    switch (s) {
    NAME_OF(LIMIT);
    }
    return "";
}
