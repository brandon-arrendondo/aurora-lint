/*
 * Rule: EXP33-C
 * Source: synthetic
 * Status: FAIL under every preset
 * Settings: static_zero_init=false
 *
 * The environment is declared not to zero static storage before main
 * (bare-metal startup that skips clearing .bss), so `cursor` holds an
 * indeterminate value on the first call and dereferencing it reads
 * through an uninitialized pointer.
 */

char next_char(void)
{
    static char *cursor;
    return *cursor;
}
