/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: PASS
 * Reason: The null terminator has more than one numeric spelling. Testing
 *         what the literal is worth, rather than matching an enumerated list
 *         of spellings, makes 0x00 and 0UL read as the terminator they are.
 */

#define NUL_HEX 0x00

int walk_hex_zero(const char *zHex) {
    int n = 0;
    char c;
    while ((c = *zHex) != 0x00) {
        n += c + *zHex;
        zHex++;
    }
    return n;
}

int walk_suffixed_zero(const char *z) {
    int n = 0;
    while (*z != 0UL) {
        n += *z;
        z++;
    }
    return n;
}

int walk_macro_hex_zero(const char *z) {
    int n = 0;
    while (*z != NUL_HEX) {
        n += *z;
        z++;
    }
    return n;
}
