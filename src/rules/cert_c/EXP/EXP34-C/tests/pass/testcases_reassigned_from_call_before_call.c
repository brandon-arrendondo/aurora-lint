/*
 * Rule: EXP34-C
 * Status: PASS - the pointer handed to `release` was reassigned from a call
 *         after its NULL initializer, so the value passed is the call's
 *         result, not NULL, and `release`'s dereference is not reached with
 *         a null parameter from these callers.
 *
 * Shape: an iterator declared `= NULL` so an error label can test it, then
 * reassigned from its constructor before use. A whole-function "last write
 * wins" table dropped the constructor write (its value is unknown) and kept
 * the NULL, reading the argument as definitely null. The assignment that
 * dominates the call is the one that decides.
 */

struct iter {
    int pos;
};

struct iter *iter_init(int start);

static void release(struct iter *it)
{
    it->pos = 0;
}

int walk_once(int start)
{
    struct iter *it = NULL;
    int n = 0;

    it = iter_init(start);
    n = it->pos;
    release(it);
    return n;
}

int walk_each(int count)
{
    struct iter *it = NULL;
    int i;

    for (i = 0; i < count; i++) {
        it = iter_init(i);
        release(it);
    }
    return count;
}

int pick(int flag, struct iter *existing)
{
    struct iter *chosen = NULL;

    if (flag) {
        chosen = existing;
        release(chosen);
    } else {
        chosen = iter_init(flag);
        release(chosen);
    }
    return flag;
}
