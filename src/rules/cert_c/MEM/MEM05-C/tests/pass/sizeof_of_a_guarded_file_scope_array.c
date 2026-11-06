/*
 * Rule: MEM05-C
 * Source: synthetic
 * Status: PASS - sizeof of a file-scope array is a constant, inside a guard and passed to a macro
 *
 * The whole file sits under one `#ifndef`, and `magic` is a file-scope
 * array, which cannot be variable-length, so `sizeof(magic) + 4` is a
 * constant. Handing `magic` to `copy`, a macro that only reads its
 * arguments, does not make it a name a macro may have declared.
 */
#ifndef OMIT_JOURNAL

#define copy(D, S, N) do { char *d = (char *)(D); const char *s = (const char *)(S); \
    unsigned long n = (N); while (n--) *d++ = *s++; } while (0)

static const unsigned char magic[] = { 0xd9, 0xd5, 0x05, 0xf9 };

void sink(void *p);

void write_header(void)
{
    unsigned char header[sizeof(magic) + 4];
    copy(header, magic, sizeof(magic));
    sink(header);
}

#endif /* OMIT_JOURNAL */
