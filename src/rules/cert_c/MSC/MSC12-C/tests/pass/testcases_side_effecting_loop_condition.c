/*
 * Rule: MSC12-C
 * Status: PASS - the loop condition itself advances the pointer, so the loop
 *         makes progress with nothing in the body and the empty body is the
 *         whole point: hostap's os_strlcpy walks the source string this way
 *         to measure it.
 */

unsigned long src_len(const char *s)
{
    const char *start = s;
    while (*s++)
        ; /* determine total src string length */
    return (unsigned long)(s - start - 1);
}
