/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A called function of the file rewrites the static index
 * Expect: count=1
 *
 * `slot` is static, but `reset` in the same file assigns it an unchecked
 * value, and it runs between the wrap and the access.
 */

int read_untrusted(void);

static unsigned int slot;
static long store[4];

void reset(void)
{
    slot = read_untrusted();
}

long record(long v)
{
    if (++slot >= 4)
        slot = 0;
    reset();
    return store[slot] + v; /* Expect: here */
}
