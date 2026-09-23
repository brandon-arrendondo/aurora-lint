/*
 * Rule: DCL13-C
 * Source: testcases
 * Status: FAIL - Should trigger DCL13-C violation
 */

/*
 * Reason: the guard for an earlier fix. A macro that only READS its
 * parameter (`(x) + 1`, `(x) < (y)`) must not make an element lvalue
 * argument count as a write, and passing `st[0]` to a real function passes
 * a value -- neither modifies `st`, so `st` is still a pointer to values
 * the function never changes and DCL13-C must still report it.
 */

#define PLUS1(x) ((x) + 1)
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

int sink(unsigned v);

unsigned read_only_through_macros(unsigned *st)
{
    unsigned a = PLUS1(st[0]);
    unsigned b = MIN(st[1], st[2]);
    return a + b + sink(st[3]);
}
