/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: FAIL - Should trigger PRE31-C violation
 *
 * The macro evaluates its argument once in one configuration and twice in
 * the other. Either may be the one compiled, so the argument is not proved
 * single-evaluation.
 */

#ifdef FAST_SQUARE
#define SQUARE(x) square_fn(x)
#else
#define SQUARE(x) ((x) * (x))
#endif

int square_fn(int x);

int next_square(int i)
{
    return SQUARE(i++);  /* VIOLATION when FAST_SQUARE is not defined */
}
