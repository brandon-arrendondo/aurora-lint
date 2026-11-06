/*
 * Rule: MEM05-C
 * Source: synthetic
 * Status: PASS - The size is the sizeof of a complete file-scope array
 *
 * `magic` is declared in the arm the function is in, so `sizeof(magic)` is a
 * constant and `header` is not a variable-length array.
 */

#ifdef WITH_JOURNAL

static const unsigned char magic[] = { 0xd9, 0xd5, 0x05, 0xf9 };

void write_header(unsigned char *out)
{
    unsigned char header[sizeof(magic) + 4];
    for (unsigned i = 0; i < sizeof(header); i++) {
        header[i] = 0;
    }
    out[0] = header[0];
}

#endif
