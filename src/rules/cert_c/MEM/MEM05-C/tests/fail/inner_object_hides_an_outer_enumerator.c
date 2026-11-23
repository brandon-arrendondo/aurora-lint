/*
 * Rule: MEM05-C
 * Source: synthetic
 * Status: FAIL - An object in an inner block hides an outer enumerator
 * Expect: count=2
 *
 * The other way round: inside the block, `slots` and `depth` are objects,
 * though enumerators of the same names enclose them, so each size reads
 * an object and the array is variable-length (C11 6.7.6.2p4).
 */
enum { depth = 2 };

void sink(char *p);

void runtime_sizes(int len)
{
    enum { slots = 4 };
    {
        int slots = len;
        int depth = len / 2;
        char by_object[slots * 2];
        char by_file_shadow[depth + 1];
        sink(by_object);
        sink(by_file_shadow);
    }
}
