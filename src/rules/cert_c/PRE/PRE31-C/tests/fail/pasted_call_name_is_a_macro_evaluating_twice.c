/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: FAIL - Should trigger PRE31-C violation
 *
 * The paste turns `next(it)` into `checked_next(it)`, and the rescan
 * expands that name too: a macro that evaluates its argument twice. The
 * argument is evaluated twice by the call the paste produces, so the
 * unpasted call's side effect gives no assurance of a single evaluation.
 */

struct iter;
int advance(struct iter *it);

static int steps;

int next(struct iter *it)
{
    (void)it;
    return ++steps;
}

#define checked_next(it) (advance(it) > 0 ? advance(it) : 0)
#define CHECKED(CALL) (checked_ ## CALL)

int step(struct iter *it)
{
    return CHECKED(next(it));  /* VIOLATION: checked_next evaluates `it` twice */
}
