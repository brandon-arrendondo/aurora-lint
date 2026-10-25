/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: FAIL - a byte-wide counter written through its pointer
 *
 * An unsigned char is an integer, not a string: rnr_count receives the
 * number of neighbor reports, held in a byte rather than a size_t.
 */
typedef unsigned char u8;

int add_neighbors(u8 *rnr_count, u8 **rnr_offset);
