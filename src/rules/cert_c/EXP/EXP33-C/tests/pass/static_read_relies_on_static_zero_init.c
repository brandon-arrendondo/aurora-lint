/*
 * Rule: EXP33-C
 * Source: synthetic
 * Status: PASS under every preset
 *
 * Static storage is zeroed before main (C11 6.7.9p10), which holds in both
 * a hosted and a freestanding environment unless the startup code skips it,
 * so `table` has determinate (zero) content. The same function with the
 * static_zero_init contract withdrawn is
 * fail/static_read_without_static_zero_init.c.
 */

int lookup(int i)
{
    static int table[8];
    return table[i & 7];
}

char next_char(void)
{
    static char buf[4];
    static char *cursor;
    if (cursor == 0) {
        cursor = buf;
    }
    return *cursor;
}
