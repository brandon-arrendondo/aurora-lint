/*
 * Rule: MEM05-C
 * Source: synthetic
 * Status: PASS - An enumerator in an inner block hides an outer object
 *
 * A name means what its innermost declaration in scope makes it (C11
 * 6.2.1p4). Inside the block, `slots` is the enumerator, an integer
 * constant, though a parameter and a file-scope object of the same name
 * enclose it, so the array has a constant size.
 */
int depth;

void sink(char *p);

void fixed_sizes(int slots)
{
    {
        enum { slots = 4, depth = 2 };
        char by_enumerator[slots * 2];
        char by_file_shadow[depth + 1];
        sink(by_enumerator);
        sink(by_file_shadow);
    }
}
